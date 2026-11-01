// A live node owns its signed discv5 address and one authenticated consensus
// TCP peer. Discovery probes bootstrap ENRs and refreshes signed candidates;
// the smaller node ID dials a discovered TCP address to avoid duplicate
// connections. A lost socket is dropped while the gossip score remains in the
// caller's service, so a later step may reconnect.
//
//   UDP discovery -> verified ENR -> TCP/Noise/Status/Metadata -> Yamux
// shortcut: one simultaneous TCP peer is supported, expand the connection
// table when multi-peer mesh scheduling is implemented.
const std = @import("std");
const enr = @import("enr.zig");
const discovery = @import("discv5_discovery.zig");
const peer = @import("p2p_peer.zig");
const gossip = @import("p2p_gossip.zig");
const control = @import("p2p_control.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: Ecdsa.KeyPair,
    listener: std.Io.net.Server,
    discovery_service: *discovery.Service,
    gossip_service: *gossip.Service,
    status: control.Status,
    metadata: control.MetaData,
    routes: ?peer.Routes = null,
    connection: ?peer.Peer = null,
    last_dial_ns: i96 = 0,

    /// Bind TCP and UDP, signing the actual bound ports in the local ENR.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, identity: Ecdsa.KeyPair, local: enr.Local, max_candidates: usize, gossip_service: *gossip.Service, status: control.Status, metadata: control.MetaData) !Service {
        if (!std.mem.eql(u8, local.fork_id[0..4], &status.fork_digest) or metadata.custody_group_count != local.custody_group_count or !std.mem.eql(u8, &gossip_service.digest, &status.fork_digest)) return error.InvalidPeerConfiguration;
        const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = local.ip, .port = local.tcp_port } };
        var listener = try address.listen(io, .{});
        errdefer listener.deinit(io);
        var advertised = local;
        advertised.tcp_port = listener.socket.address.ip4.port;
        const disc = try allocator.create(discovery.Service);
        errdefer allocator.destroy(disc);
        disc.* = try discovery.Service.init(allocator, io, identity, advertised, max_candidates);
        return .{ .allocator = allocator, .io = io, .identity = identity, .listener = listener, .discovery_service = disc, .gossip_service = gossip_service, .status = status, .metadata = metadata };
    }

    /// Close the active peer, discovery socket, TCP listener, and owned table.
    pub fn deinit(self: *Service) void {
        if (self.connection) |*active| active.deinit();
        self.discovery_service.deinit();
        self.allocator.destroy(self.discovery_service);
        self.listener.deinit(self.io);
    }

    /// Return the signed local ENR URI for another node's bootstrap config.
    pub fn localUri(self: *const Service) ![]u8 {
        return self.discovery_service.localUri();
    }

    /// Verify and retain a bootstrap ENR; the next step starts its probe.
    pub fn addBootstrap(self: *Service, uri: []const u8) !void {
        return self.discovery_service.addBootstrap(uri);
    }

    /// Borrow the block and column views used for future inbound requests.
    pub fn setRoutes(self: *Service, routes: peer.Routes) void {
        self.routes = routes;
        if (self.connection) |*active| active.setRoutes(routes);
    }

    /// Report whether one fully checked peer has an active gossip stream.
    pub fn connected(self: *const Service) bool {
        return self.connection != null;
    }

    /// Borrow the active peer for validated block and column requests.
    pub fn activePeer(self: *Service) !*peer.Peer {
        return if (self.connection) |*active| active else error.NoPeer;
    }

    /// Poll discovery, listener, and active peer once within a bounded wait.
    pub fn step(self: *Service, timeout_ms: u32) !void {
        try self.discovery_service.maintain();
        if (self.connection == null and (self.last_dial_ns == 0 or now(self.io) - self.last_dial_ns >= 2 * std.time.ns_per_s)) {
            for (self.discovery_service.candidates.items.items) |candidate| {
                if (std.mem.order(u8, &self.discovery_service.local_record.node_id, &candidate.node_id) != .lt) continue;
                if (self.discovery_service.discoveredRecord(candidate.node_id) == null) continue;
                self.last_dial_ns = now(self.io);
                var active = peer.Peer.dial(self.allocator, self.io, self.identity, self.discovery_service, self.gossip_service, self.status, self.metadata, candidate.node_id) catch break;
                if (self.routes) |routes| active.setRoutes(routes);
                self.connection = active;
                return;
            }
        }
        var descriptors: [3]std.posix.pollfd = undefined;
        var count: usize = 0;
        descriptors[count] = .{ .fd = self.discovery_service.socket.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        count += 1;
        descriptors[count] = .{ .fd = self.listener.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        count += 1;
        if (self.connection) |*active| {
            descriptors[count] = .{ .fd = active.connection.stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
            count += 1;
        }
        if (try std.posix.poll(descriptors[0..count], @intCast(@min(timeout_ms, std.math.maxInt(i32)))) == 0) return;
        if (descriptors[0].revents & std.posix.POLL.IN != 0) {
            self.discovery_service.step(.{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(1) } }) catch |err| switch (err) {
                error.Timeout => {},
                else => return err,
            };
        }
        if (descriptors[1].revents & std.posix.POLL.IN != 0) {
            const stream = try self.listener.accept(self.io);
            if (self.connection != null) {
                stream.close(self.io);
            } else {
                var active = try peer.Peer.accept(self.allocator, self.io, stream, self.identity, self.discovery_service, self.gossip_service, self.status, self.metadata);
                if (self.routes) |routes| active.setRoutes(routes);
                self.connection = active;
            }
        }
        if (count == 3 and descriptors[2].revents != 0) {
            const active = if (self.connection) |*value| value else return;
            active.step() catch |err| switch (err) {
                error.EndOfStream, error.ConnectionResetByPeer, error.PeerBanned => {
                    active.deinit();
                    self.connection = null;
                },
                else => return err,
            };
        }
    }

    /// Publish serialized SSZ through the current authenticated gossip stream.
    pub fn publish(self: *Service, topic: []const u8, ssz_bytes: []const u8) !void {
        const active = if (self.connection) |*value| value else return error.NoPeer;
        return active.publish(topic, ssz_bytes);
    }
};

/// Return the awake monotonic clock used to space connection retries.
fn now(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

test "two live services discover and connect without a transport address" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ingress = @import("p2p_ingress.zig");
    const fulu = @import("fulu");
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    const digest = try config.digestAtSlot(0);
    const Validators = struct {
        /// Accept a block after the service's ingress gates.
        fn block(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {}
        /// Accept an attestation after the service's ingress gates.
        fn attestation(_: *anyopaque, _: *const fulu.Attestation) !void {}
        /// Accept an aggregate after the service's ingress gates.
        fn aggregate(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    };
    var marker: u8 = 0;
    const block_gate = ingress.BlockValidation{ .context = &marker, .validate = Validators.block };
    const attestation_gate = ingress.AttestationValidation{ .context = &marker, .validate = Validators.attestation };
    const aggregate_gate = ingress.AggregateValidation{ .context = &marker, .validate = Validators.aggregate };
    var gossip_a = try gossip.Service.init(allocator, config, digest, &.{}, 1, 3, block_gate, attestation_gate, aggregate_gate, null);
    defer gossip_a.deinit();
    var gossip_b = try gossip.Service.init(allocator, config, digest, &.{}, 1, 3, block_gate, attestation_gate, aggregate_gate, null);
    defer gossip_b.deinit();
    var fork_id = [_]u8{0} ** 16;
    @memcpy(fork_id[0..4], &digest);
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 0, .tcp_port = 0, .fork_id = fork_id, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    const status = control.Status{ .fork_digest = digest, .finalized_root = .{0} ** 32, .finalized_epoch = 0, .head_root = .{0} ** 32, .head_slot = 0, .earliest_available_slot = 0 };
    const metadata = control.MetaData{ .seq_number = 1, .attnets = .{ .data = [_]bool{false} ** 64 }, .syncnets = .{ .data = [_]bool{false} ** 4 }, .custody_group_count = 4 };
    var a = try Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{121} ** 32), local, 2, &gossip_a, status, metadata);
    defer a.deinit();
    var b = try Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{122} ** 32), local, 2, &gossip_b, status, metadata);
    defer b.deinit();
    const b_uri = try b.localUri();
    defer allocator.free(b_uri);
    try a.addBootstrap(b_uri);
    const Context = struct {
        service: *Service,
        attempts: usize = 200,
        err: ?anyerror = null,

        /// Drive the second node until its authenticated peer is connected.
        fn run(self: *@This()) void {
            for (0..self.attempts) |_| {
                self.service.step(10) catch |err| {
                    self.err = err;
                    return;
                };
                if (self.service.connected()) return;
            }
            self.err = error.ConnectionTimeout;
        }
    };
    var context = Context{ .service = &b };
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    for (0..200) |_| {
        try a.step(10);
        if (a.connected()) break;
    }
    thread.join();
    if (context.err) |err| return err;
    try std.testing.expect(a.connected());
    try std.testing.expect(b.connected());
    try std.testing.expectEqual(b.discovery_service.local_record.tcp_port, a.discovery_service.discoveredRecord(b.discovery_service.local_record.node_id).?.tcp_port);
    gossip_a.peers.noteInvalid(b.discovery_service.local_record.node_id);
    b.connection.?.deinit();
    b.connection = null;
    try a.step(10);
    try std.testing.expect(!a.connected());
    context.err = null;
    context.attempts = 400;
    const retry_thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    for (0..400) |_| {
        try a.step(10);
        if (a.connected()) break;
    }
    retry_thread.join();
    if (context.err) |err| return err;
    try std.testing.expect(a.connected());
    try std.testing.expect(b.connected());
    try std.testing.expectEqual(@as(u8, 1), gossip_a.peers.state(b.discovery_service.local_record.node_id).?.invalid_messages);
}
