// Multistream-select chooses the application protocol on an authenticated peer
// stream before any gossip or Req/Resp bytes are exchanged. Each line has a
// varint byte length including its trailing newline. The responder echoes the
// header, then echoes an exact supported ID or sends "na"; only an echoed ID
// lets the initiator pass subsequent bytes to the chosen protocol decoder.
//
//   initiator: header -> proposal -> application bytes
//   responder: header -> echo -> proposal -> echo / na
// A line is limited to 128 bytes, including its newline.
const std = @import("std");
const wire = @import("p2p_wire.zig");

const header = "/multistream/1.0.0";
const unavailable = "na";
const max_line_size = 128;

pub const Protocol = enum {
    gossip,
    status,
    ping,
    metadata,
    blocks_by_root,
    blocks_by_range,
    columns_by_root,
    columns_by_range,

    /// Return the exact protocol ID, including the Req/Resp encoding suffix.
    pub fn id(self: Protocol) []const u8 {
        return switch (self) {
            .gossip => "/meshsub/1.1.0",
            .status => "/eth2/beacon_chain/req/status/2/ssz_snappy",
            .ping => "/eth2/beacon_chain/req/ping/1/ssz_snappy",
            .metadata => "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
            .blocks_by_root => "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
            .blocks_by_range => "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
            .columns_by_root => "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy",
            .columns_by_range => "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy",
        };
    }

    /// Map a negotiated Req/Resp ID to its existing payload codec.
    pub fn request(self: Protocol) ?wire.Protocol {
        return switch (self) {
            .gossip => null,
            .status => .status,
            .ping => .ping,
            .metadata => .metadata,
            .blocks_by_root => .blocks_by_root,
            .blocks_by_range => .blocks_by_range,
            .columns_by_root => .columns_by_root,
            .columns_by_range => .columns_by_range,
        };
    }
};

const Event = union(enum) { header, unavailable, protocol: Protocol, unsupported };

/// Hold at most one partial multistream line across transport reads.
pub const Decoder = struct {
    bytes: [max_line_size]u8 = undefined,
    length: usize = 0,
    received: usize = 0,
    prefix: u8 = 0,

    pub const Result = struct { consumed: usize, event: ?Event };

    /// Consume through one complete line; return its event and any unread tail.
    pub fn feed(self: *Decoder, input: []const u8) !Result {
        for (input, 0..) |byte, index| {
            if (self.length == 0) {
                if (self.prefix == 0) {
                    if (byte < 0x80) {
                        if (byte == 0 or byte > max_line_size) return error.InvalidLength;
                        self.length = byte;
                    } else {
                        self.prefix = byte;
                    }
                    continue;
                }
                if (byte == 0 or byte > 1 or (byte == 1 and self.prefix & 0x7f != 0)) return error.InvalidLength;
                self.length = @as(usize, self.prefix & 0x7f) | (@as(usize, byte) << 7);
                self.prefix = 0;
                if (self.length > max_line_size) return error.InvalidLength;
                continue;
            }
            self.bytes[self.received] = byte;
            self.received += 1;
            if (self.received != self.length) continue;
            const line = self.bytes[0..self.length];
            if (line[line.len - 1] != '\n' or std.mem.indexOfScalar(u8, line[0 .. line.len - 1], '\n') != null) return error.InvalidLine;
            const value = line[0 .. line.len - 1];
            for (value) |character| {
                if (character < 0x20 or character > 0x7e) return error.InvalidLine;
            }
            const event: Event = if (std.mem.eql(u8, value, header)) .header else if (std.mem.eql(u8, value, unavailable)) .unavailable else blk: {
                for (std.meta.tags(Protocol)) |protocol| {
                    if (std.mem.eql(u8, value, protocol.id())) break :blk .{ .protocol = protocol };
                }
                break :blk .unsupported;
            };
            self.length = 0;
            self.received = 0;
            return .{ .consumed = index + 1, .event = event };
        }
        return .{ .consumed = input.len, .event = null };
    }
};

/// Encode a supported line, including its canonical varint and newline.
fn encodeLine(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const length = value.len + 1;
    if (length > max_line_size) return error.InvalidLength;
    const prefix_size: usize = if (length < 128) 1 else 2;
    const result = try allocator.alloc(u8, prefix_size + length);
    if (prefix_size == 1) {
        result[0] = @intCast(length);
    } else {
        result[0] = @as(u8, @intCast(length & 0x7f)) | 0x80;
        result[1] = @intCast(length >> 7);
    }
    @memcpy(result[prefix_size..][0..value.len], value);
    result[result.len - 1] = '\n';
    return result;
}

/// Build the initiator's optimistic header and exact protocol proposal.
pub fn offer(allocator: std.mem.Allocator, protocol: Protocol) ![]u8 {
    const first = try encodeLine(allocator, header);
    defer allocator.free(first);
    const second = try encodeLine(allocator, protocol.id());
    defer allocator.free(second);
    return std.mem.concat(allocator, u8, &.{ first, second });
}

/// Answer one event at a time, leaving unread application bytes with the caller.
pub const Responder = struct {
    decoder: Decoder = .{},
    phase: enum { header, proposal, selected } = .header,

    pub const Result = struct { consumed: usize, response: ?[]u8 = null, selected: ?Protocol = null };

    /// Consume one negotiation line; the caller owns any response bytes.
    pub fn feed(self: *Responder, allocator: std.mem.Allocator, input: []const u8) !Result {
        if (self.phase == .selected) return error.InvalidNegotiation;
        const parsed = try self.decoder.feed(input);
        const event = parsed.event orelse return .{ .consumed = parsed.consumed };
        if (self.phase == .header) {
            if (event != .header) return error.InvalidNegotiation;
            self.phase = .proposal;
            return .{ .consumed = parsed.consumed, .response = try encodeLine(allocator, header) };
        }
        switch (event) {
            .protocol => |protocol| {
                const response = try encodeLine(allocator, protocol.id());
                self.phase = .selected;
                return .{ .consumed = parsed.consumed, .response = response, .selected = protocol };
            },
            .unsupported => return .{ .consumed = parsed.consumed, .response = try encodeLine(allocator, unavailable) },
            else => return error.InvalidNegotiation,
        }
    }
};

/// Require a matching header and exact protocol echo before stream dispatch.
pub const Initiator = struct {
    decoder: Decoder = .{},
    protocol: Protocol,
    phase: enum { header, confirmation, selected } = .header,

    pub const Result = struct { consumed: usize, selected: bool = false };

    /// Consume one reply line and report when application bytes may follow.
    pub fn feed(self: *Initiator, input: []const u8) !Result {
        if (self.phase == .selected) return error.InvalidNegotiation;
        const parsed = try self.decoder.feed(input);
        const event = parsed.event orelse return .{ .consumed = parsed.consumed };
        if (self.phase == .header) {
            if (event != .header) return error.InvalidNegotiation;
            self.phase = .confirmation;
            return .{ .consumed = parsed.consumed };
        }
        switch (event) {
            .protocol => |protocol| {
                if (protocol != self.protocol) return error.InvalidNegotiation;
                self.phase = .selected;
                return .{ .consumed = parsed.consumed, .selected = true };
            },
            .unavailable => return error.ProtocolUnavailable,
            else => return error.InvalidNegotiation,
        }
    }
};

test "exact gossip and request IDs negotiate across split and combined reads" {
    const allocator = std.testing.allocator;
    for ([_]Protocol{ .gossip, .status, .columns_by_range }) |protocol| {
        const sent = try offer(allocator, protocol);
        defer allocator.free(sent);
        var responder: Responder = .{};
        var initiator: Initiator = .{ .protocol = protocol };
        const partial = try responder.feed(allocator, sent[0..1]);
        try std.testing.expectEqual(@as(?[]u8, null), partial.response);
        const first = try responder.feed(allocator, sent[1..]);
        defer allocator.free(first.response.?);
        const second = try responder.feed(allocator, sent[1 + first.consumed ..]);
        defer allocator.free(second.response.?);
        try std.testing.expectEqual(protocol, second.selected.?);
        const reply = try std.mem.concat(allocator, u8, &.{ first.response.?, second.response.? });
        defer allocator.free(reply);
        const received_header = try initiator.feed(reply);
        const received_protocol = try initiator.feed(reply[received_header.consumed..]);
        try std.testing.expect(received_protocol.selected);
    }
}

test "negotiated request IDs match existing payload codecs" {
    for (std.meta.tags(Protocol)) |protocol| {
        const request = protocol.request() orelse continue;
        try std.testing.expect(std.mem.startsWith(u8, protocol.id(), request.id()));
        try std.testing.expectEqualStrings("ssz_snappy", protocol.id()[request.id().len..]);
    }
}

test "unknown proposal gets na and cannot select a protocol" {
    const allocator = std.testing.allocator;
    var responder: Responder = .{};
    const first = try encodeLine(allocator, header);
    defer allocator.free(first);
    const header_reply = try responder.feed(allocator, first);
    defer allocator.free(header_reply.response.?);
    const unknown = try encodeLine(allocator, "/meshsub/1.2.0");
    defer allocator.free(unknown);
    const rejected = try responder.feed(allocator, unknown);
    defer allocator.free(rejected.response.?);
    try std.testing.expectEqualSlices(u8, &.{ 3, 'n', 'a', '\n' }, rejected.response.?);
    try std.testing.expectEqual(@as(?Protocol, null), rejected.selected);
    var initiator: Initiator = .{ .protocol = .gossip };
    _ = try initiator.feed(header_reply.response.?);
    try std.testing.expectError(error.ProtocolUnavailable, initiator.feed(rejected.response.?));
}

test "malformed framing and mismatched echoes are rejected" {
    var decoder: Decoder = .{};
    try std.testing.expectError(error.InvalidLength, decoder.feed(&.{0}));
    decoder = .{};
    try std.testing.expectError(error.InvalidLength, decoder.feed(&.{ 0x80, 0 }));
    decoder = .{};
    try std.testing.expectError(error.InvalidLength, decoder.feed(&.{ 0x81, 1 }));
    decoder = .{};
    try std.testing.expectError(error.InvalidLength, decoder.feed(&.{ 0x81, 2 }));
    decoder = .{};
    try std.testing.expectError(error.InvalidLine, decoder.feed(&.{ 2, 'x', 'y' }));
    const allocator = std.testing.allocator;
    var initiator: Initiator = .{ .protocol = .status };
    const first = try encodeLine(allocator, header);
    defer allocator.free(first);
    _ = try initiator.feed(first);
    const wrong = try encodeLine(allocator, Protocol.ping.id());
    defer allocator.free(wrong);
    try std.testing.expectError(error.InvalidNegotiation, initiator.feed(wrong));
}
