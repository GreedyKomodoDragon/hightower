// A discv5 session uses different AES-GCM keys in each direction. Every sent
// nonce must be unique under its key, and every received nonce must be used
// only once. Keep a bounded set of authenticated inbound nonces; stop using
// the session when its packet budget is exhausted so old nonces stay rejected.
//
//   fresh handshake keys -> unique outbound nonce -> authenticated packet
//   authenticated inbound packet -> peer check -> replay check -> message
// Handshake key derivation supplies the keys; this module never reuses them.
const std = @import("std");
const packets = @import("discv5_packets.zig");

pub const Session = struct {
    allocator: std.mem.Allocator,
    local_id: [32]u8,
    remote_id: [32]u8,
    send_key: [16]u8,
    receive_key: [16]u8,
    nonce_prefix: [4]u8,
    masking_prefix: [8]u8,
    packet_limit: usize,
    sent: u64 = 0,
    received: std.AutoHashMap([12]u8, void),

    /// Open a session with fresh directional keys and a budget of 1..4096 packets.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, local_id: [32]u8, remote_id: [32]u8, send_key: [16]u8, receive_key: [16]u8, packet_limit: usize) !Session {
        if (packet_limit == 0 or packet_limit > 4096 or std.mem.eql(u8, &local_id, &remote_id)) return error.InvalidSession;
        var nonce_prefix: [4]u8 = undefined;
        var masking_prefix: [8]u8 = undefined;
        io.random(&nonce_prefix);
        io.random(&masking_prefix);
        return .{ .allocator = allocator, .local_id = local_id, .remote_id = remote_id, .send_key = send_key, .receive_key = receive_key, .nonce_prefix = nonce_prefix, .masking_prefix = masking_prefix, .packet_limit = packet_limit, .received = .init(allocator) };
    }

    /// Release the replay table after all returned plaintext has been freed.
    pub fn deinit(self: *Session) void {
        self.received.deinit();
    }

    /// Encode a packet with a new nonce and masking IV; the caller owns its bytes.
    pub fn send(self: *Session, plaintext: []const u8) ![]u8 {
        if (self.sent >= self.packet_limit) return error.SessionExhausted;
        var nonce: [12]u8 = undefined;
        @memcpy(nonce[0..4], &self.nonce_prefix);
        std.mem.writeInt(u64, nonce[4..12], self.sent, .big);
        var masking_iv: [16]u8 = undefined;
        @memcpy(masking_iv[0..8], &self.masking_prefix);
        std.mem.writeInt(u64, masking_iv[8..16], self.sent, .big);
        const encoded = try packets.encodeOrdinary(self.allocator, self.remote_id, self.local_id, masking_iv, nonce, self.send_key, plaintext);
        self.sent += 1;
        return encoded;
    }

    /// Authenticate one packet, rejecting a wrong peer or reused nonce before delivery.
    pub fn receive(self: *Session, packet: []const u8) !packets.Ordinary {
        if (self.received.count() >= self.packet_limit) return error.SessionExhausted;
        const decoded = try packets.decodeOrdinary(self.allocator, self.local_id, self.receive_key, packet);
        errdefer decoded.deinit(self.allocator);
        if (!std.mem.eql(u8, &decoded.source_id, &self.remote_id)) return error.WrongPeer;
        if (self.received.contains(decoded.nonce)) return error.ReplayedPacket;
        try self.received.put(decoded.nonce, {});
        return decoded;
    }
};

test "directional sessions deliver once, reject tampering, and stop at their packet budget" {
    const messages = @import("discv5_messages.zig");
    const allocator = std.testing.allocator;
    const a_id = [_]u8{0x11} ** 32;
    const b_id = [_]u8{0x22} ** 32;
    const a_to_b = [_]u8{0x33} ** 16;
    const b_to_a = [_]u8{0x44} ** 16;
    var a = try Session.init(allocator, std.testing.io, a_id, b_id, a_to_b, b_to_a, 2);
    defer a.deinit();
    var b = try Session.init(allocator, std.testing.io, b_id, a_id, b_to_a, a_to_b, 2);
    defer b.deinit();
    const request_id = try messages.RequestId.init(&.{1});
    const plaintext = try messages.encode(allocator, .{ .ping = .{ .request_id = request_id, .enr_sequence = 7 } });
    defer allocator.free(plaintext);
    const first = try a.send(plaintext);
    defer allocator.free(first);
    const tampered = try allocator.dupe(u8, first);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, b.receive(tampered));
    const received = try b.receive(first);
    defer received.deinit(allocator);
    try std.testing.expectEqualSlices(u8, plaintext, received.plaintext);
    try std.testing.expectError(error.ReplayedPacket, b.receive(first));
    const second = try a.send(plaintext);
    defer allocator.free(second);
    try std.testing.expect(!std.mem.eql(u8, first, second));
    const received_second = try b.receive(second);
    defer received_second.deinit(allocator);
    try std.testing.expectError(error.SessionExhausted, a.send(plaintext));
    try std.testing.expectError(error.SessionExhausted, b.receive(first));
    const reverse = try b.send(plaintext);
    defer allocator.free(reverse);
    const received_reverse = try a.receive(reverse);
    defer received_reverse.deinit(allocator);
    try std.testing.expectEqual(b_id, received_reverse.source_id);
}
