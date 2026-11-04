// A live node owns its signed discv5 address and one authenticated consensus
// TCP peer. Discovery probes bootstrap ENRs and refreshes signed candidates;
// any discovered TCP address may be dialled so a single configured bootstrap
// still connects. Reciprocal dials are resolved by node ID: the larger ID
// keeps the inbound stream and both sides discard the duplicate. A lost socket
// is dropped while the gossip score remains in the caller's service, so a
// later step may reconnect.
//
//   UDP discovery -> verified ENR -> TCP/Noise/Status/Metadata -> Yamux
// shortcut: one simultaneous TCP peer is supported, expand the connection
// table when multi-peer mesh scheduling is implemented.
const std = @import("std");
const enr = @import("enr.zig");
const discovery = @import("discv5_discovery.zig");
const peer = @import("p2p_peer.zig");
const tcp = @import("p2p_tcp.zig");
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
    pending_dial: ?*Dial = null,
    last_handshake_error: ?anyerror = null,
    last_dial_ns: i96 = 0,

    const Dial = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        identity: Ecdsa.KeyPair,
        peers: *discovery.Service,
        peer_id: [32]u8,
        thread: std.Thread = undefined,
        done: std.atomic.Value(bool) = .init(false),
        connection: ?tcp.Connection = null,
        err: ?anyerror = null,

        /// Establish only the authenticated transport; the service thread owns the remaining exchanges.
        fn run(self: *Dial) void {
            self.connection = tcp.Connection.dial(self.allocator, self.io, self.identity, self.peers, self.peer_id) catch |err| {
                self.err = err;
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };

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
        if (self.pending_dial) |dial| {
            dial.thread.join();
            if (dial.connection) |*connection| connection.deinit();
            self.allocator.destroy(dial);
        }
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

    /// Authenticate an inbound stream and resolve reciprocal dials by node ID.
    fn acceptInbound(self: *Service, stream: std.Io.net.Stream) !void {
        var transport = try tcp.Connection.accept(self.allocator, self.io, stream, self.identity, self.discovery_service);
        if (self.pending_dial) |dial| {
            if (std.mem.eql(u8, &dial.peer_id, &transport.peer_id) and !keepInbound(self.discovery_service.local_record.node_id, transport.peer_id)) {
                transport.deinit();
                return;
            }
        }
        var accepted = try peer.Peer.finishAccept(self.allocator, transport, self.discovery_service, self.gossip_service, self.status, self.metadata, self.routes);
        if (self.connection) |*existing| {
            const same_peer = std.mem.eql(u8, &existing.connection.peer_id, &accepted.connection.peer_id);
            if (!same_peer or !keepInbound(self.discovery_service.local_record.node_id, accepted.connection.peer_id)) {
                accepted.deinit();
                return;
            }
            if (self.routes) |routes| accepted.setRoutes(routes);
            existing.deinit();
            self.connection = accepted;
            return;
        }
        self.connection = accepted;
    }

    /// Drop the active peer after a stream-fatal error.
    fn dropPeer(self: *Service) void {
        if (self.connection) |*active| active.deinit();
        self.connection = null;
    }

    /// Poll discovery, listener, and active peer once within a bounded wait.
    pub fn step(self: *Service, timeout_ms: u32) !void {
        // The dial worker reads discovered ENRs until it finishes.
        if (self.pending_dial == null) try self.discovery_service.maintain();
        if (self.connection == null and self.pending_dial == null and (self.last_dial_ns == 0 or now(self.io) - self.last_dial_ns >= 2 * std.time.ns_per_s)) {
            self.last_dial_ns = now(self.io);
            for (self.discovery_service.candidates.items.items) |candidate| {
                if (self.discovery_service.discoveredRecord(candidate.node_id) == null) continue;
                const dial = try self.allocator.create(Dial);
                errdefer self.allocator.destroy(dial);
                dial.* = .{ .allocator = self.allocator, .io = self.io, .identity = self.identity, .peers = self.discovery_service, .peer_id = candidate.node_id };
                dial.thread = try std.Thread.spawn(.{}, Dial.run, .{dial});
                self.pending_dial = dial;
                break;
            }
        }
        var descriptors: [3]std.posix.pollfd = undefined;
        var count: usize = 0;
        descriptors[count] = .{ .fd = self.discovery_service.socket.socket.handle, .events = if (self.pending_dial == null) std.posix.POLL.IN else 0, .revents = 0 };
        count += 1;
        descriptors[count] = .{ .fd = self.listener.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        count += 1;
        if (self.connection) |*active| {
            descriptors[count] = .{ .fd = active.connection.stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
            count += 1;
        }
        _ = try std.posix.poll(descriptors[0..count], @intCast(@min(timeout_ms, std.math.maxInt(i32))));
        if (descriptors[0].revents & std.posix.POLL.IN != 0 and self.pending_dial == null) {
            self.discovery_service.step(.{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(1) } }) catch |err| switch (err) {
                // Unknown challenges are unauthenticated or stale datagrams;
                // ignore them so discovery keeps serving valid peers.
                error.Timeout, error.UnknownChallenge => {},
                else => return err,
            };
        }
        if (descriptors[1].revents & std.posix.POLL.IN != 0) {
            const stream = try self.listener.accept(self.io);
            self.acceptInbound(stream) catch |err| {
                self.last_handshake_error = err;
                if (err == error.OutOfMemory) return err;
            };
            return;
        }
        if (self.pending_dial) |dial| {
            if (dial.done.load(.acquire)) {
                dial.thread.join();
                self.pending_dial = null;
                defer self.allocator.destroy(dial);
                if (dial.connection) |transport| {
                    if (self.connection != null) {
                        var duplicate = transport;
                        duplicate.deinit();
                    } else {
                        self.connection = peer.Peer.finishDial(self.allocator, transport, self.discovery_service, self.gossip_service, self.status, self.metadata, dial.peer_id, self.routes) catch |err| {
                            self.last_handshake_error = err;
                            if (err == error.OutOfMemory) return err;
                            return;
                        };
                    }
                } else if (dial.err) |err| {
                    self.last_handshake_error = err;
                    if (err == error.OutOfMemory) return err;
                }
            }
        }
        if (count == 3 and descriptors[2].revents != 0) {
            const active = if (self.connection) |*value| value else return;
            // Every peer error invalidates the stream: receive may have
            // consumed part of a transport record before failing.
            active.step() catch |err| {
                self.dropPeer();
                if (err == error.OutOfMemory) return err;
            };
        }
    }

    /// Publish serialized SSZ through the current authenticated gossip stream.
    pub fn publish(self: *Service, topic: []const u8, ssz_bytes: []const u8) !void {
        const active = if (self.connection) |*value| value else return error.NoPeer;
        return active.publish(topic, ssz_bytes);
    }
};

/// Return whether the larger local node ID should retain a reciprocal inbound stream.
fn keepInbound(local_id: [32]u8, remote_id: [32]u8) bool {
    return std.mem.order(u8, &local_id, &remote_id) == .gt;
}

/// Return the awake monotonic clock used to space connection retries.
fn now(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

test "service ignores an inbound stream that fails authentication" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ingress = @import("p2p_ingress.zig");
    const fulu = @import("fulu");
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    const digest = try config.digestAtSlot(0);
    var marker: u8 = 0;
    const block_gate = ingress.BlockValidation{ .context = &marker, .validate = struct {
        /// Accept blocks after the service's ingress gates.
        fn accept(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {}
    }.accept };
    const attestation_gate = ingress.AttestationValidation{ .context = &marker, .validate = struct {
        /// Accept attestations after the service's ingress gates.
        fn accept(_: *anyopaque, _: *const fulu.Attestation) !void {}
    }.accept };
    const aggregate_gate = ingress.AggregateValidation{ .context = &marker, .validate = struct {
        /// Accept aggregates after the service's ingress gates.
        fn accept(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    }.accept };
    var gossip_service = try gossip.Service.init(allocator, config, digest, &.{}, 1, 3, block_gate, attestation_gate, aggregate_gate, null);
    defer gossip_service.deinit();
    var fork_id = [_]u8{0} ** 16;
    @memcpy(fork_id[0..4], &digest);
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 0, .tcp_port = 0, .fork_id = fork_id, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    const status = control.Status{ .fork_digest = digest, .finalized_root = .{0} ** 32, .finalized_epoch = 0, .head_root = .{0} ** 32, .head_slot = 0, .earliest_available_slot = 0 };
    const metadata = control.MetaData{ .seq_number = 1, .attnets = .{ .data = [_]bool{false} ** 64 }, .syncnets = .{ .data = [_]bool{false} ** 4 }, .custody_group_count = 4 };
    var service = try Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{123} ** 32), local, 2, &gossip_service, status, metadata);
    defer service.deinit();
    var intrusive = try service.listener.socket.address.connect(io, .{ .mode = .stream });
    var write_buffer: [64]u8 = undefined;
    var writer = intrusive.writer(io, &write_buffer);
    try writer.interface.writeAll("not a noise handshake");
    try writer.interface.flush();
    intrusive.close(io);
    try service.step(20);
    try std.testing.expect(!service.connected());
    try service.step(20);
    try std.testing.expect(!service.connected());
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
        err: ?anyerror = null,
        done: std.atomic.Value(bool) = .init(false),
        ready: std.atomic.Value(bool) = .init(false),
        start: std.atomic.Value(bool) = .init(true),

        /// Drive the second node until its authenticated peer is connected.
        fn run(self: *@This()) void {
            defer self.done.store(true, .release);
            self.ready.store(true, .release);
            while (!self.start.load(.acquire)) std.atomic.spinLoopHint();
            const deadline = now(self.service.io) + 15 * std.time.ns_per_s;
            while (now(self.service.io) < deadline) {
                self.service.step(10) catch |err| {
                    self.err = err;
                    return;
                };
                if (self.service.connected()) return;
            }
            self.err = self.service.last_handshake_error orelse error.ConnectionTimeout;
        }
    };
    var context = Context{ .service = &b };
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    var first_joined = false;
    defer if (!first_joined) thread.join();
    const initial_deadline = now(io) + 20 * std.time.ns_per_s;
    while ((!context.done.load(.acquire) or !a.connected()) and now(io) < initial_deadline) {
        try a.step(10);
    }
    thread.join();
    first_joined = true;
    if (context.err) |err| return err;
    if (!a.connected()) return a.last_handshake_error orelse error.ConnectionTimeout;
    try std.testing.expect(a.connected());
    try std.testing.expect(b.connected());
    try std.testing.expect(a.connection.?.connection.initiator != b.connection.?.connection.initiator);
    try std.testing.expectEqual(b.discovery_service.local_record.tcp_port, a.discovery_service.discoveredRecord(b.discovery_service.local_record.node_id).?.tcp_port);
    gossip_a.peers.noteInvalid(b.discovery_service.local_record.node_id);
    b.connection.?.deinit();
    b.connection = null;
    const disconnect_deadline = now(io) + 15 * std.time.ns_per_s;
    while (now(io) < disconnect_deadline) {
        try a.step(10);
        if (!a.connected()) break;
    }
    try std.testing.expect(!a.connected());
    // Both signed records are now verified; release both service loops together.
    try a.discovery_service.addTrusted(b.discovery_service.local_record);
    try b.discovery_service.addTrusted(a.discovery_service.local_record);
    a.last_dial_ns = 0;
    b.last_dial_ns = 0;
    a.last_handshake_error = null;
    b.last_handshake_error = null;
    context.err = null;
    context.done.store(false, .release);
    context.ready.store(false, .release);
    context.start.store(false, .release);
    const retry_thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    var retry_joined = false;
    defer if (!retry_joined) retry_thread.join();
    while (!context.ready.load(.acquire)) std.atomic.spinLoopHint();
    context.start.store(true, .release);
    const retry_deadline = now(io) + 20 * std.time.ns_per_s;
    while ((!context.done.load(.acquire) or !a.connected()) and now(io) < retry_deadline) {
        try a.step(10);
    }
    retry_thread.join();
    retry_joined = true;
    if (context.err) |err| return err;
    if (!a.connected()) return a.last_handshake_error orelse error.ConnectionTimeout;
    try std.testing.expect(a.connected());
    try std.testing.expect(b.connected());
    try std.testing.expectEqualSlices(u8, &a.discovery_service.local_record.node_id, &b.connection.?.connection.peer_id);
    try std.testing.expectEqualSlices(u8, &b.discovery_service.local_record.node_id, &a.connection.?.connection.peer_id);
    try std.testing.expect(a.connection.?.connection.initiator != b.connection.?.connection.initiator);
    try std.testing.expectEqual(@as(u8, 1), gossip_a.peers.state(b.discovery_service.local_record.node_id).?.invalid_messages);
    try b.connection.?.connection.send(.{ .kind = .data, .stream_id = 99 });
    for (0..100) |_| {
        try a.step(10);
        if (!a.connected()) break;
    }
    try std.testing.expect(!a.connected());
}

test "larger node id keeps the inbound side of a reciprocal dial" {
    try std.testing.expect(!keepInbound([_]u8{1} ** 32, [_]u8{2} ** 32));
    try std.testing.expect(keepInbound([_]u8{2} ** 32, [_]u8{1} ** 32));
    try std.testing.expect(!keepInbound([_]u8{1} ** 32, [_]u8{1} ** 32));
}
