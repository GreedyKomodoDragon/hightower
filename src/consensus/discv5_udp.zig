// Discv5 exchanges bounded UDP datagrams at the address advertised by a
// verified ENR. The UDP source address is checked against that ENR after the
// packet's identity proof is verified; otherwise a relay could move a valid
// challenge or session packet to another endpoint. A receive buffer has one
// extra byte so an oversized datagram is rejected instead of truncated into
// a valid-sized packet.
//
//   verified ENR -> UDP endpoint -> bounded datagram -> identity/session gate
// This IPv4 transport accepts discv5 packets of 63..1280 bytes.
const std = @import("std");
const enr = @import("enr.zig");
const packets = @import("discv5_packets.zig");

pub const Datagram = struct {
    from: std.Io.net.IpAddress,
    bytes: []u8,
};

pub const Socket = struct {
    io: std.Io,
    socket: std.Io.net.Socket,

    /// Bind an IPv4 UDP socket; port zero asks the OS to choose an available port.
    pub fn bind(io: std.Io, ip: [4]u8, port: u16) !Socket {
        const bind_address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = ip, .port = port } };
        return .{ .io = io, .socket = try bind_address.bind(io, .{ .mode = .dgram }) };
    }

    /// Close the UDP socket after all pending sends and receives complete.
    pub fn deinit(self: *Socket) void {
        self.socket.close(self.io);
    }

    /// Return the bound IPv4 endpoint, including an OS-selected port.
    pub fn address(self: *const Socket) std.Io.net.IpAddress {
        return self.socket.address;
    }

    /// Send a bounded packet to a previously verified ENR's UDP endpoint.
    pub fn send(self: *const Socket, record: enr.Record, packet: []const u8) !void {
        if (packet.len < packets.min_packet_size or packet.len > packets.max_packet_size) return error.InvalidPacketSize;
        const destination = endpoint(record);
        try self.socket.send(self.io, &destination, packet);
    }

    /// Receive one whole bounded packet; the returned bytes borrow caller storage.
    pub fn receive(self: *const Socket, buffer: *[packets.max_packet_size + 1]u8, timeout: std.Io.Timeout) !Datagram {
        const incoming = try self.socket.receiveTimeout(self.io, buffer, timeout);
        if (incoming.flags.trunc or incoming.data.len < packets.min_packet_size or incoming.data.len > packets.max_packet_size) return error.InvalidPacketSize;
        return .{ .from = incoming.from, .bytes = incoming.data };
    }
};

/// Return an IPv4 UDP endpoint from a previously verified signed ENR.
pub fn endpoint(record: enr.Record) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = record.ip, .port = record.udp_port } };
}

/// Bind an authenticated peer packet to the UDP endpoint in its verified ENR.
pub fn requireEndpoint(record: enr.Record, source: std.Io.net.IpAddress) !void {
    switch (source) {
        .ip4 => |actual| {
            if (actual.port != record.udp_port or !std.mem.eql(u8, &actual.bytes, &record.ip)) return error.WrongEndpoint;
        },
        .ip6 => return error.WrongEndpoint,
    }
}

test "two UDP sockets exchange a bounded WHOAREYOU at the signed ENR endpoint" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    var sender = try Socket.bind(io, .{ 127, 0, 0, 1 }, 0);
    defer sender.deinit();
    var recipient = try Socket.bind(io, .{ 127, 0, 0, 1 }, 0);
    defer recipient.deinit();
    const signing_key = try Ecdsa.KeyPair.generateDeterministic([_]u8{41} ** 32);
    const recipient_key = try Ecdsa.KeyPair.generateDeterministic([_]u8{42} ** 32);
    const local = enr.Local{
        .sequence = 1,
        .ip = .{ 127, 0, 0, 1 },
        .udp_port = recipient.address().ip4.port,
        .tcp_port = 9001,
        .fork_id = .{ 1, 2, 3, 4, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 },
        .next_fork_digest = .{0} ** 4,
        .custody_group_count = 4,
    };
    const signed = try enr.encode(allocator, recipient_key, local);
    defer allocator.free(signed);
    const record = try enr.decode(allocator, signed);
    const packet = packets.encodeWhoAreYou(record.node_id, [_]u8{1} ** 16, .{
        .request_nonce = [_]u8{2} ** 12,
        .id_nonce = [_]u8{3} ** 16,
        .enr_sequence = 0,
    });
    try sender.send(record, &packet);
    var buffer: [packets.max_packet_size + 1]u8 = undefined;
    const received = try recipient.receive(&buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try std.testing.expectEqualSlices(u8, &packet, received.bytes);
    const sender_record_bytes = try enr.encode(allocator, signing_key, .{
        .sequence = 1,
        .ip = .{ 127, 0, 0, 1 },
        .udp_port = sender.address().ip4.port,
        .tcp_port = 9002,
        .fork_id = local.fork_id,
        .next_fork_digest = .{0} ** 4,
        .custody_group_count = 4,
    });
    defer allocator.free(sender_record_bytes);
    const sender_record = try enr.decode(allocator, sender_record_bytes);
    try requireEndpoint(sender_record, received.from);
    try std.testing.expectError(error.WrongEndpoint, requireEndpoint(record, received.from));
    try std.testing.expectError(error.InvalidPacketSize, sender.send(record, packet[0..62]));
    try std.testing.expectError(error.InvalidPacketSize, sender.send(record, &([_]u8{0} ** 1281)));
    const destination = endpoint(record);
    try sender.socket.send(io, &destination, &([_]u8{0} ** 1300));
    try std.testing.expectError(error.InvalidPacketSize, recipient.receive(&buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } }));
    try std.testing.expectError(error.Timeout, recipient.receive(&buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(20) } }));
}
