// Discv5 bootstraps peers through a challenge and an authenticated first
// message. A probe from a configured ENR prompts WHOAREYOU; its response must
// come from the probed UDP endpoint and echo the probe nonce. The recipient
// keeps a bounded, short-lived challenge tied to the source endpoint and node
// ID. A verified handshake can update the peer table and create a responder
// session; configured bootstrap ENRs are verified before an initiator probes.
// FINDNODE requests then exchange signed ENRs at authenticated XOR distances;
// admission follows signature, fork, and distance checks.
//
//   ENR probe -> WHOAREYOU -> verified handshake PING -> session PONG
//   session FINDNODE -> bounded NODES -> verified candidate table
// At most 256 peers and challenges are retained; challenges expire after 1 s.
// FINDNODE replies have 10 s for a caller-driven, multi-packet exchange.
const std = @import("std");
const enr = @import("enr.zig");
const bootstrap = @import("discovery_bootstrap.zig");
const udp = @import("discv5_udp.zig");
const packets = @import("discv5_packets.zig");
const handshake = @import("discv5_handshake.zig");
const messages = @import("discv5_messages.zig");
const Session = @import("discv5_session.zig").Session;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const challenge_lifetime_ns = std.time.ns_per_s;
const findnode_lifetime_ns = 10 * std.time.ns_per_s;

const Probe = struct {
    nonce: [12]u8,
    request_id: messages.RequestId,
    endpoint: std.Io.net.IpAddress,
    started_ns: i96,
};
const FindQuery = struct {
    request: messages.FindNode,
    started_ns: i96,
    total: u8 = 0,
    received: u8 = 0,
};
const Peer = struct {
    id: [32]u8,
    session: ?Session = null,
    probe: ?Probe = null,
    expected_pong: ?messages.RequestId = null,
    find_query: ?FindQuery = null,
    discovered: bool = false,
};
const PendingChallenge = struct {
    id: [32]u8,
    endpoint: std.Io.net.IpAddress,
    data: [63]u8,
    started_ns: i96,
};

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    key_pair: Ecdsa.KeyPair,
    socket: udp.Socket,
    local_enr: []u8,
    local_record: enr.Record,
    candidates: bootstrap.Candidates,
    peers: std.ArrayList(Peer) = .empty,
    challenges: std.ArrayList(PendingChallenge) = .empty,

    /// Bind UDP, sign the local ENR, and allocate a discovery table of 1..256 peers.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, key_pair: Ecdsa.KeyPair, local: enr.Local, max_peers: usize) !Service {
        var socket = try udp.Socket.bind(io, local.ip, local.udp_port);
        errdefer socket.deinit();
        var advertised = local;
        advertised.udp_port = socket.address().ip4.port;
        const local_enr = try enr.encode(allocator, key_pair, advertised);
        errdefer allocator.free(local_enr);
        const local_record = try enr.decode(allocator, local_enr);
        const candidates = try bootstrap.Candidates.init(allocator, local.fork_id[0..4].*, max_peers);
        return .{ .allocator = allocator, .io = io, .key_pair = key_pair, .socket = socket, .local_enr = local_enr, .local_record = local_record, .candidates = candidates };
    }

    /// Release sessions, challenge tables, the signed ENR, and the UDP socket.
    pub fn deinit(self: *Service) void {
        for (self.peers.items) |*peer| if (peer.session) |*session| session.deinit();
        self.peers.deinit(self.allocator);
        self.challenges.deinit(self.allocator);
        self.candidates.deinit();
        self.allocator.free(self.local_enr);
        self.socket.deinit();
    }

    /// Return an owned `enr:` URI for configuring another node's bootstrap list.
    pub fn localUri(self: *const Service) ![]u8 {
        const encoded = try self.allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(self.local_enr.len));
        defer self.allocator.free(encoded);
        _ = std.base64.url_safe_no_pad.Encoder.encode(encoded, self.local_enr);
        return std.fmt.allocPrint(self.allocator, "enr:{s}", .{encoded});
    }

    /// Admit a configured bootstrap ENR after signature and fork checks.
    pub fn addBootstrap(self: *Service, uri: []const u8) !void {
        return self.candidates.add(uri);
    }

    /// Send a fresh unauthenticated probe to a verified bootstrap candidate.
    pub fn probe(self: *Service, id: [32]u8) !void {
        const record = self.candidates.get(id) orelse return error.UnknownPeer;
        const peer = try self.ensurePeer(id);
        var nonce: [12]u8 = undefined;
        var iv: [16]u8 = undefined;
        var request_bytes: [8]u8 = undefined;
        self.io.random(&nonce);
        self.io.random(&iv);
        self.io.random(&request_bytes);
        const request_id = try messages.RequestId.init(&request_bytes);
        const plaintext = try messages.encode(self.allocator, .{ .ping = .{ .request_id = request_id, .enr_sequence = self.local_record.sequence } });
        defer self.allocator.free(plaintext);
        const packet = try packets.encodeOrdinary(self.allocator, id, self.local_record.node_id, iv, nonce, [_]u8{0} ** 16, plaintext);
        defer self.allocator.free(packet);
        try self.socket.send(record, packet);
        peer.probe = .{ .nonce = nonce, .request_id = request_id, .endpoint = udp.endpoint(record), .started_ns = self.now() };
        peer.expected_pong = request_id;
        peer.discovered = false;
    }

    /// Ask an authenticated peer for signed ENRs at up to 16 XOR distances.
    pub fn findNode(self: *Service, id: [32]u8, distances: []const u16) !void {
        if (distances.len == 0 or distances.len > 16) return error.InvalidDistance;
        const peer = self.findPeer(id) orelse return error.UnknownPeer;
        if (!peer.discovered or peer.session == null) return error.UnknownSession;
        if (peer.find_query) |query| {
            if (self.now() - query.started_ns <= findnode_lifetime_ns) return error.RequestInProgress;
        }
        var request_bytes: [8]u8 = undefined;
        self.io.random(&request_bytes);
        var request = messages.FindNode{ .request_id = try messages.RequestId.init(&request_bytes), .count = @intCast(distances.len) };
        for (distances, 0..) |distance, index| {
            if (distance > 256) return error.InvalidDistance;
            request.distances[index] = distance;
        }
        const plaintext = try messages.encode(self.allocator, .{ .findnode = request });
        defer self.allocator.free(plaintext);
        const packet = try peer.session.?.send(plaintext);
        defer self.allocator.free(packet);
        const record = self.candidates.get(id) orelse return error.UnknownPeer;
        try self.socket.send(record, packet);
        peer.find_query = .{ .request = request, .started_ns = self.now() };
    }

    /// Receive and process one UDP datagram within the caller's timeout.
    pub fn step(self: *Service, timeout: std.Io.Timeout) !void {
        var buffer: [packets.max_packet_size + 1]u8 = undefined;
        const datagram = try self.socket.receive(&buffer, timeout);
        return self.handle(datagram);
    }

    /// Return a discovered peer's signed address for the consensus transport.
    pub fn discoveredRecord(self: *const Service, id: [32]u8) ?enr.Record {
        for (self.peers.items) |peer| {
            if (std.mem.eql(u8, &peer.id, &id) and peer.discovered) return self.candidates.get(id);
        }
        return null;
    }

    /// Route one bounded datagram through its packet-specific authentication gate.
    fn handle(self: *Service, datagram: udp.Datagram) !void {
        const header = try packets.inspect(self.local_record.node_id, datagram.bytes);
        return switch (header.kind) {
            .ordinary => self.handleOrdinary(datagram),
            .whoareyou => self.handleWhoAreYou(datagram, header),
            .handshake => self.handleHandshake(datagram),
        };
    }

    /// Challenge unknown or stale ordinary sessions; process authenticated PING/PONG.
    fn handleOrdinary(self: *Service, datagram: udp.Datagram) !void {
        const source_id = try self.claimedSource(datagram.bytes);
        const peer = self.findPeer(source_id) orelse return self.sendChallenge(source_id, datagram);
        const record = self.candidates.get(source_id) orelse return self.sendChallenge(source_id, datagram);
        udp.requireEndpoint(record, datagram.from) catch return self.sendChallenge(source_id, datagram);
        const session = if (peer.session) |*existing| existing else return self.sendChallenge(source_id, datagram);
        const decoded = session.receive(datagram.bytes) catch |err| switch (err) {
            error.AuthenticationFailed, error.SessionExhausted => return self.sendChallenge(source_id, datagram),
            else => return err,
        };
        defer decoded.deinit(self.allocator);
        if (decoded.plaintext.len > 0 and decoded.plaintext[0] == 4) return self.handleNodes(peer, decoded.plaintext);
        const message = try messages.decode(self.allocator, decoded.plaintext);
        switch (message) {
            .ping => |ping| return self.sendPong(session, record, datagram.from, ping.request_id),
            .pong => |pong| {
                const expected = peer.expected_pong orelse return error.UnsolicitedPong;
                if (!std.mem.eql(u8, expected.slice(), pong.request_id.slice())) return error.WrongRequestId;
                peer.expected_pong = null;
                peer.discovered = true;
            },
            .findnode => |find| return self.sendNodes(peer, record, find),
        }
    }

    /// Answer a matching WHOAREYOU from the probed endpoint with a signed handshake.
    fn handleWhoAreYou(self: *Service, datagram: udp.Datagram, header: packets.Header) !void {
        _ = try packets.decodeWhoAreYou(self.local_record.node_id, datagram.bytes);
        for (self.peers.items) |*peer| {
            const pending_probe = peer.probe orelse continue;
            if (!std.meta.eql(pending_probe.endpoint, datagram.from) or !std.mem.eql(u8, &pending_probe.nonce, &header.nonce)) continue;
            if (self.expired(pending_probe.started_ns)) return error.ChallengeExpired;
            const record = self.candidates.get(peer.id) orelse return error.UnknownPeer;
            var iv: [16]u8 = undefined;
            var nonce: [12]u8 = undefined;
            var ephemeral_seed: [32]u8 = undefined;
            self.io.random(&iv);
            self.io.random(&nonce);
            self.io.random(&ephemeral_seed);
            const ephemeral = try Ecdsa.KeyPair.generateDeterministic(ephemeral_seed);
            const challenge_data = try packets.challengeData(self.local_record.node_id, datagram.bytes);
            const plaintext = try messages.encode(self.allocator, .{ .ping = .{ .request_id = pending_probe.request_id, .enr_sequence = self.local_record.sequence } });
            defer self.allocator.free(plaintext);
            const sent = try handshake.encodePacket(self.allocator, self.key_pair, self.local_enr, record, challenge_data, ephemeral.secret_key, iv, nonce, plaintext);
            defer sent.deinit(self.allocator);
            var session = try Session.init(self.allocator, self.io, self.local_record.node_id, peer.id, sent.keys.initiator, sent.keys.recipient, 4096);
            errdefer session.deinit();
            try self.socket.send(record, sent.bytes);
            if (peer.session) |*old| old.deinit();
            peer.session = session;
            peer.probe = null;
            return;
        }
        return error.UnknownChallenge;
    }

    /// Accept one endpoint-bound handshake and send its PONG through the new session.
    fn handleHandshake(self: *Service, datagram: udp.Datagram) !void {
        const source_id = try self.claimedSource(datagram.bytes);
        for (self.challenges.items, 0..) |pending, index| {
            if (!std.mem.eql(u8, &pending.id, &source_id) or !std.meta.eql(pending.endpoint, datagram.from)) continue;
            if (self.expired(pending.started_ns)) return error.ChallengeExpired;
            const accepted = try handshake.decodePacket(self.allocator, self.local_record.node_id, self.key_pair.secret_key, pending.data, self.candidates.get(source_id), self.candidates.fork_digest, datagram.bytes);
            defer accepted.deinit(self.allocator);
            try udp.requireEndpoint(accepted.record, datagram.from);
            const message = try messages.decode(self.allocator, accepted.plaintext);
            const ping = switch (message) {
                .ping => |value| value,
                else => return error.InvalidHandshakeMessage,
            };
            var session = try Session.init(self.allocator, self.io, self.local_record.node_id, source_id, accepted.keys.recipient, accepted.keys.initiator, 4096);
            errdefer session.deinit();
            if (accepted.enr_bytes) |bytes| {
                try self.candidates.addSigned(bytes);
            } else {
                try self.candidates.addVerified(accepted.record);
            }
            const peer = try self.ensurePeer(source_id);
            try self.sendPong(&session, accepted.record, datagram.from, ping.request_id);
            if (peer.session) |*old| old.deinit();
            peer.session = session;
            peer.discovered = true;
            peer.expected_pong = null;
            _ = self.challenges.swapRemove(index);
            return;
        }
        return error.UnknownChallenge;
    }

    /// Send a one-time WHOAREYOU challenge tied to source ID and UDP endpoint.
    fn sendChallenge(self: *Service, source_id: [32]u8, datagram: udp.Datagram) !void {
        const header = try packets.inspect(self.local_record.node_id, datagram.bytes);
        var id_nonce: [16]u8 = undefined;
        var iv: [16]u8 = undefined;
        self.io.random(&id_nonce);
        self.io.random(&iv);
        const sequence = if (self.candidates.get(source_id)) |record| record.sequence else 0;
        const reply = packets.encodeWhoAreYou(source_id, iv, .{ .request_nonce = header.nonce, .id_nonce = id_nonce, .enr_sequence = sequence });
        const data = try packets.challengeData(source_id, &reply);
        var index: usize = 0;
        while (index < self.challenges.items.len) {
            if (self.expired(self.challenges.items[index].started_ns)) {
                _ = self.challenges.swapRemove(index);
                continue;
            }
            index += 1;
        }
        for (self.challenges.items) |*pending| {
            if (!std.mem.eql(u8, &pending.id, &source_id) or !std.meta.eql(pending.endpoint, datagram.from)) continue;
            return;
        }
        if (self.challenges.items.len >= self.candidates.max_peers) return error.PeerLimitReached;
        try self.socket.socket.send(self.io, &datagram.from, &reply);
        try self.challenges.append(self.allocator, .{ .id = source_id, .endpoint = datagram.from, .data = data, .started_ns = self.now() });
    }

    /// Send a PONG using the authenticated session and observed UDP endpoint.
    fn sendPong(self: *Service, session: *Session, record: enr.Record, from: std.Io.net.IpAddress, request_id: messages.RequestId) !void {
        const observed = switch (from) {
            .ip4 => |ip| ip,
            .ip6 => return error.WrongEndpoint,
        };
        var ip: [16]u8 = [_]u8{0} ** 16;
        @memcpy(ip[0..4], &observed.bytes);
        const plaintext = try messages.encode(self.allocator, .{ .pong = .{ .request_id = request_id, .enr_sequence = self.local_record.sequence, .recipient_ip = ip, .ip_len = 4, .recipient_port = observed.port } });
        defer self.allocator.free(plaintext);
        const packet = try session.send(plaintext);
        defer self.allocator.free(packet);
        return self.socket.send(record, packet);
    }

    /// Reply with at most 16 signed ENRs, one per bounded NODES datagram.
    fn sendNodes(self: *Service, peer: *Peer, requester: enr.Record, find: messages.FindNode) !void {
        const session = if (peer.session) |*existing| existing else return error.UnknownSession;
        var selected: [16][]const u8 = undefined;
        var count: usize = 0;
        if (hasDistance(find, 0)) {
            selected[count] = self.local_enr;
            count += 1;
        }
        for (self.candidates.items.items) |record| {
            if (count == selected.len) break;
            if (std.mem.eql(u8, &record.node_id, &requester.node_id)) continue;
            if (!hasDistance(find, logDistance(self.local_record.node_id, record.node_id))) continue;
            selected[count] = self.candidates.raw(record.node_id) orelse continue;
            count += 1;
        }
        const total: u8 = @intCast(@max(count, 1));
        if (count == 0) return self.sendNodesChunk(session, requester, find.request_id, total, &.{});
        for (selected[0..count]) |wire| try self.sendNodesChunk(session, requester, find.request_id, total, &.{wire});
    }

    /// Send one signed ENR or an empty result through a directional session.
    fn sendNodesChunk(self: *Service, session: *Session, requester: enr.Record, request_id: messages.RequestId, total: u8, records: []const []const u8) !void {
        const plaintext = try messages.encodeNodes(self.allocator, request_id, total, records, self.candidates.fork_digest);
        defer self.allocator.free(plaintext);
        const packet = try session.send(plaintext);
        defer self.allocator.free(packet);
        return self.socket.send(requester, packet);
    }

    /// Verify a NODES reply's request ID and distances before adding candidates.
    fn handleNodes(self: *Service, peer: *Peer, plaintext: []const u8) !void {
        const query = if (peer.find_query) |*pending| pending else return error.UnsolicitedNodes;
        if (self.now() - query.started_ns > findnode_lifetime_ns) return error.RequestExpired;
        const nodes = try messages.decodeNodes(self.allocator, plaintext, self.candidates.fork_digest);
        if (!std.mem.eql(u8, query.request.request_id.slice(), nodes.request_id.slice())) return error.WrongRequestId;
        if (query.total != 0 and query.total != nodes.total or query.received >= nodes.total) return error.InvalidNodes;
        for (nodes.records[0..nodes.count]) |record| {
            if (!hasDistance(query.request, logDistance(peer.id, record.node_id))) return error.InvalidDistance;
        }
        for (0..nodes.count) |index| try self.candidates.addSigned(nodes.raw(index));
        query.total = nodes.total;
        query.received += 1;
        if (query.received == query.total) peer.find_query = null;
    }

    /// Read the untrusted source ID used only for routing to a validation gate.
    fn claimedSource(self: *const Service, packet: []const u8) ![32]u8 {
        const header = try packets.inspect(self.local_record.node_id, packet);
        if (header.kind == .whoareyou) return error.InvalidPacketHeader;
        var plain: [55]u8 = undefined;
        packets.mask(self.local_record.node_id, packet[0..16].*, &plain, packet[16..71]);
        return plain[23..55].*;
    }

    /// Find mutable state for a node ID without trusting its current packet.
    fn findPeer(self: *Service, id: [32]u8) ?*Peer {
        for (self.peers.items) |*peer| if (std.mem.eql(u8, &peer.id, &id)) return peer;
        return null;
    }

    /// Create at most one session slot per verified candidate.
    fn ensurePeer(self: *Service, id: [32]u8) !*Peer {
        if (self.findPeer(id)) |peer| return peer;
        if (self.peers.items.len >= self.candidates.max_peers) return error.PeerLimitReached;
        try self.peers.append(self.allocator, .{ .id = id });
        return &self.peers.items[self.peers.items.len - 1];
    }

    /// Return the current monotonic nanoseconds for bounded challenge lifetimes.
    fn now(self: *const Service) i96 {
        return std.Io.Clock.awake.now(self.io).nanoseconds;
    }

    /// Reject a probe or challenge more than one second old.
    fn expired(self: *const Service, started_ns: i96) bool {
        return self.now() - started_ns > challenge_lifetime_ns;
    }
};

/// Return the bit length of the big-endian XOR distance between node IDs.
fn logDistance(a: [32]u8, b: [32]u8) u16 {
    for (a, b, 0..) |left, right, index| {
        const difference: u8 = left ^ right;
        if (difference != 0) return @intCast(256 - index * 8 - @clz(difference));
    }
    return 0;
}

/// Check whether a FINDNODE request includes a given logarithmic distance.
fn hasDistance(request: messages.FindNode, distance: u16) bool {
    for (request.distances[0..request.count]) |requested| if (requested == distance) return true;
    return false;
}

test "two bootstrap nodes discover and reconnect through live UDP handshakes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key_a = try Ecdsa.KeyPair.generateDeterministic([_]u8{71} ** 32);
    const key_b = try Ecdsa.KeyPair.generateDeterministic([_]u8{72} ** 32);
    const fork_id = [16]u8{ 1, 2, 3, 4, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 };
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 0, .tcp_port = 9000, .fork_id = fork_id, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    var a = try Service.init(allocator, io, key_a, local, 2);
    defer a.deinit();
    const a_uri = try a.localUri();
    defer allocator.free(a_uri);
    const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } };
    const short_timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(20) } };
    var first_b_port: u16 = undefined;
    {
        var b = try Service.init(allocator, io, key_b, local, 2);
        defer b.deinit();
        first_b_port = b.local_record.udp_port;
        const b_uri = try b.localUri();
        defer allocator.free(b_uri);
        try a.addBootstrap(b_uri);
        try a.probe(b.local_record.node_id);
        try b.step(timeout);
        try std.testing.expectEqual(@as(usize, 0), b.candidates.items.items.len);
        try a.probe(b.local_record.node_id);
        try b.step(timeout);
        try std.testing.expectEqual(@as(usize, 1), b.challenges.items.len);
        try std.testing.expectError(error.UnknownChallenge, a.step(timeout));
        b.challenges.items[0].started_ns -= 2 * challenge_lifetime_ns;
        try a.probe(b.local_record.node_id);
        try b.step(timeout);
        try a.step(timeout);
        b.challenges.items[0].started_ns -= 2 * challenge_lifetime_ns;
        try std.testing.expectError(error.ChallengeExpired, b.step(timeout));
        try std.testing.expectEqual(@as(usize, 0), b.candidates.items.items.len);
        try a.probe(b.local_record.node_id);
        try b.step(timeout);
        try a.step(timeout);
        try b.step(timeout);
        try a.step(timeout);
        try std.testing.expectEqual(first_b_port, a.discoveredRecord(b.local_record.node_id).?.udp_port);
        try std.testing.expectEqual(a.local_record.node_id, b.discoveredRecord(a.local_record.node_id).?.node_id);
    }
    try std.testing.expectError(error.Timeout, a.step(short_timeout));
    var restarted = local;
    restarted.sequence = 2;
    var b_again = try Service.init(allocator, io, key_b, restarted, 2);
    defer b_again.deinit();
    try b_again.addBootstrap(a_uri);
    try b_again.probe(a.local_record.node_id);
    try a.step(timeout);
    try b_again.step(timeout);
    try a.step(timeout);
    try b_again.step(timeout);
    try std.testing.expectEqual(b_again.local_record.udp_port, a.discoveredRecord(b_again.local_record.node_id).?.udp_port);
    try std.testing.expect(b_again.discoveredRecord(a.local_record.node_id) != null);
}

test "FINDNODE shares verified ENRs and rejects wrong-distance NODES" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 0, .tcp_port = 9000, .fork_id = .{ 1, 2, 3, 4, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } };
    var a = try Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{81} ** 32), local, 3);
    defer a.deinit();
    var b = try Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{82} ** 32), local, 3);
    defer b.deinit();
    var c = try Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{83} ** 32), local, 3);
    defer c.deinit();
    const b_uri = try b.localUri();
    defer allocator.free(b_uri);
    try a.addBootstrap(b_uri);
    try a.probe(b.local_record.node_id);
    try b.step(timeout);
    try a.step(timeout);
    try b.step(timeout);
    try a.step(timeout);
    const c_uri = try c.localUri();
    defer allocator.free(c_uri);
    try b.addBootstrap(c_uri);
    try b.probe(c.local_record.node_id);
    try c.step(timeout);
    try b.step(timeout);
    try c.step(timeout);
    try b.step(timeout);
    try std.testing.expect(a.candidates.get(c.local_record.node_id) == null);

    try a.findNode(b.local_record.node_id, &.{0});
    const request_id = a.findPeer(b.local_record.node_id).?.find_query.?.request.request_id;
    const b_peer = b.findPeer(a.local_record.node_id).?;
    const b_session = if (b_peer.session) |*session| session else return error.MissingSession;
    try b.sendNodesChunk(b_session, a.local_record, request_id, 1, &.{b.candidates.raw(c.local_record.node_id).?});
    try std.testing.expectError(error.InvalidDistance, a.step(timeout));
    try std.testing.expect(a.candidates.get(c.local_record.node_id) == null);
    try b.step(timeout);
    a.findPeer(b.local_record.node_id).?.find_query.?.started_ns -= 2 * std.time.ns_per_s;
    try a.step(timeout);
    try std.testing.expect(a.findPeer(b.local_record.node_id).?.find_query == null);

    try a.findNode(b.local_record.node_id, &.{logDistance(b.local_record.node_id, c.local_record.node_id)});
    try b.step(timeout);
    a.findPeer(b.local_record.node_id).?.find_query.?.started_ns -= findnode_lifetime_ns + 1;
    try std.testing.expectError(error.RequestExpired, a.step(timeout));
    try std.testing.expect(a.candidates.get(c.local_record.node_id) == null);
    try a.findNode(b.local_record.node_id, &.{logDistance(b.local_record.node_id, c.local_record.node_id)});
    try b.step(timeout);
    try a.step(timeout);
    try std.testing.expectEqual(c.local_record.node_id, a.candidates.get(c.local_record.node_id).?.node_id);
    try a.probe(c.local_record.node_id);
    try c.step(timeout);
    try a.step(timeout);
    try c.step(timeout);
    try a.step(timeout);
    try std.testing.expect(a.discoveredRecord(c.local_record.node_id) != null);
}

test "logarithmic distance counts the highest differing bit" {
    const zero = [_]u8{0} ** 32;
    var one = zero;
    one[31] = 1;
    try std.testing.expectEqual(@as(u16, 0), logDistance(zero, zero));
    try std.testing.expectEqual(@as(u16, 1), logDistance(zero, one));
    one[0] = 0x80;
    try std.testing.expectEqual(@as(u16, 256), logDistance(zero, one));
}
