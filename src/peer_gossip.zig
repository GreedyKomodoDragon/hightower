// Execution peers exchange pool hashes over authenticated discv5 and RLPx.
// Discovery verifies signed ENRs and their UDP source before any TCP dial;
// eth/69 Status checks chain identity before pool data is accepted. Work is
// bounded to two sessions, 64 candidates, 256 hashes, 3 MiB of transaction
// bytes, and one outstanding transaction request per peer.
//
// ENR -> UDP proof -> RLPx/Status -> hash request -> shared pool admission
const std = @import("std");
const execution = @import("execution");
const consensus = @import("consensus");
const enr = consensus.ENR;
const discovery = consensus.Discv5Discovery;
const rpc = execution.rpc;
const rlpx = @import("rlpx");
const peer = rlpx.peer;
const eth = rlpx.eth;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const max_peers: usize = 2;
const max_candidates: usize = 64;
const max_invalid: u8 = 3;
const announce_interval_ns: i96 = std.time.ns_per_s;
const dial_interval_ns: i96 = 2 * std.time.ns_per_s;
const request_timeout_ns: i96 = 10 * std.time.ns_per_s;

const Slot = struct {
    connection: peer.Peer,
    id: [32]u8,
    cursor: usize = 0,
    last_announce_ns: i96 = 0,
    pending_id: ?u64 = null,
    pending_since_ns: i96 = 0,
    pending_hashes: [eth.max_hashes][32]u8 = .{.{0} ** 32} ** eth.max_hashes,
    pending_count: usize = 0,
    request_id: u64 = 0,
    invalid: u8 = 0,
};

const Handshake = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: Ecdsa.KeyPair,
    status: eth.Status,
    inbound: ?std.Io.net.Stream = null,
    outbound: ?struct { id: [32]u8, key: Ecdsa.PublicKey, address: std.Io.net.IpAddress } = null,
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    connection: ?peer.Peer = null,
    failure: ?anyerror = null,

    /// Complete one bounded RLPx setup without holding the gossip loop.
    fn run(self: *Handshake) void {
        const established = if (self.outbound) |target|
            peer.Peer.dial(self.allocator, self.io, self.identity, target.key, target.address, self.status)
        else
            peer.Peer.accept(self.allocator, self.io, self.inbound.?, self.identity, self.status);
        self.connection = established catch |err| {
            self.failure = err;
            self.done.store(true, .release);
            return;
        };
        self.done.store(true, .release);
    }
};

/// Owns the execution identity, discovery socket, TCP listener, and two sessions.
pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *rpc.Server,
    identity: Ecdsa.KeyPair,
    listener: std.Io.net.Server,
    discovery_service: discovery.Service,
    genesis_hash: [32]u8,
    fork_hash: [4]u8,
    slots: [max_peers]?Slot = .{ null, null },
    pending: [max_peers]?*Handshake = .{ null, null },
    last_dial_ns: i96 = 0,
    next_candidate_index: usize = 0,

    /// Bind execution TCP and UDP on one port and verify configured seed ENRs.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, server: *rpc.Server, identity: Ecdsa.KeyPair, bind: std.Io.net.IpAddress, advertised_ip: [4]u8, seeds: []const []const u8, genesis_hash: [32]u8) !Service {
        var listener = try bind.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        var fork_hash: [4]u8 = undefined;
        std.mem.writeInt(u32, &fork_hash, std.hash.Crc32.hash(&genesis_hash), .big);
        var fork_id: [16]u8 = .{0} ** 16;
        @memcpy(fork_id[0..4], &fork_hash);
        const advertised = enr.Local{
            .sequence = @intCast(@max(1, std.Io.Clock.real.now(io).nanoseconds)),
            .ip = advertised_ip,
            .udp_port = listener.socket.address.ip4.port,
            .tcp_port = listener.socket.address.ip4.port,
            .fork_id = fork_id,
            .next_fork_digest = .{0} ** 4,
            .custody_group_count = 4,
        };
        // shortcut: execution ENRs reuse the signed fork-gated codec; use generic ENRs when public EL bootnodes are supported.
        var disc = try discovery.Service.initWithBind(allocator, io, identity, advertised, bind.ip4.bytes, max_candidates);
        errdefer disc.deinit();
        for (seeds) |seed| try disc.addBootstrap(seed);
        return .{ .allocator = allocator, .io = io, .server = server, .identity = identity, .listener = listener, .discovery_service = disc, .genesis_hash = genesis_hash, .fork_hash = fork_hash };
    }

    /// Log the signed bootstrap ENR and run the peer loop beside RPC.
    pub fn start(self: *Service) !void {
        const uri = try self.discovery_service.localUri();
        defer self.allocator.free(uri);
        std.log.info("execution peer ENR: {s}", .{uri});
        const thread = try std.Thread.spawn(.{}, run, .{self});
        thread.detach();
    }

    /// Drive discovery, inbound connections, outbound dials, and bounded gossip.
    fn run(self: *Service) void {
        const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(50) } };
        while (true) {
            self.discovery_service.step(timeout) catch |err| {
                if (err != error.Timeout) std.log.warn("execution peer discovery: {s}", .{@errorName(err)});
            };
            self.collectReady();
            self.acceptReady() catch |err| std.log.warn("execution peer accept: {s}", .{@errorName(err)});
            self.connectReady() catch |err| std.log.warn("execution peer dial: {s}", .{@errorName(err)});
            for (0..max_peers) |index| {
                if (self.slots[index] == null) continue;
                self.stepSlot(index) catch |err| {
                    std.log.warn("execution peer disconnected: {s}", .{@errorName(err)});
                    self.drop(index);
                };
            }
        }
    }

    /// Move one accepted socket to a bounded handshake worker.
    fn acceptReady(self: *Service) !void {
        var descriptors = [_]std.posix.pollfd{.{ .fd = self.listener.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        if (try std.posix.poll(&descriptors, 0) == 0) return;
        const stream = try self.listener.accept(self.io);
        const index = self.freePending() orelse {
            stream.close(self.io);
            return;
        };
        if (self.reservedCount() >= max_peers) {
            stream.close(self.io);
            return;
        }
        errdefer stream.close(self.io);
        const task = try self.allocator.create(Handshake);
        errdefer self.allocator.destroy(task);
        task.* = .{ .allocator = self.allocator, .io = self.io, .identity = self.identity, .status = try self.localStatus(), .inbound = stream };
        task.thread = try std.Thread.spawn(.{}, Handshake.run, .{task});
        self.pending[index] = task;
    }

    /// Start one verified outbound connection without blocking active peers.
    fn connectReady(self: *Service) !void {
        const index = self.freePending() orelse return;
        if (self.reservedCount() >= max_peers) return;
        for (self.pending) |task| if (task) |active| {
            if (active.outbound != null) return;
        };
        const now_ns = now(self.io);
        if (now_ns - self.last_dial_ns < dial_interval_ns) return;
        const candidates = self.discovery_service.candidates.items.items;
        for (0..candidates.len) |offset| {
            const candidate_index = (self.next_candidate_index + offset) % candidates.len;
            const record = candidates[candidate_index];
            if (std.mem.order(u8, &self.discovery_service.local_record.node_id, &record.node_id) != .lt or self.hasPeer(record.node_id)) continue;
            if (self.discovery_service.discoveredRecord(record.node_id) == null or !safeEndpoint(self.discovery_service.local_record.ip, record.ip)) continue;
            self.last_dial_ns = now_ns;
            self.next_candidate_index = (candidate_index + 1) % candidates.len;
            const remote = try Ecdsa.PublicKey.fromSec1(&record.public_key);
            const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = record.ip, .port = record.tcp_port } };
            const task = try self.allocator.create(Handshake);
            errdefer self.allocator.destroy(task);
            task.* = .{ .allocator = self.allocator, .io = self.io, .identity = self.identity, .status = try self.localStatus(), .outbound = .{ .id = record.node_id, .key = remote, .address = address } };
            task.thread = try std.Thread.spawn(.{}, Handshake.run, .{task});
            self.pending[index] = task;
            return;
        }
    }

    /// Adopt completed authenticated sessions only after rechecking discovery and capacity.
    fn collectReady(self: *Service) void {
        for (&self.pending) |*item| {
            const task = item.* orelse continue;
            if (!task.done.load(.acquire)) continue;
            task.thread.?.join();
            item.* = null;
            defer self.allocator.destroy(task);
            if (task.failure) |err| {
                std.log.warn("execution peer handshake: {s}", .{@errorName(err)});
                continue;
            }
            var connection = task.connection.?;
            const id = nodeId(connection.remote);
            const record = self.discovery_service.discoveredRecord(id) orelse {
                connection.deinit();
                continue;
            };
            const compressed = connection.remote.toCompressedSec1();
            const expected = if (task.outbound) |target| std.mem.eql(u8, &target.id, &id) else true;
            const slot_index = self.freeSlot();
            if (!expected or !std.mem.eql(u8, &record.public_key, &compressed) or !safeEndpoint(self.discovery_service.local_record.ip, record.ip) or self.hasPeer(id) or slot_index == null) {
                connection.deinit();
                continue;
            }
            self.slots[slot_index.?] = .{ .connection = connection, .id = id };
        }
    }

    /// Process at most one frame and one rotating announcement per loop.
    fn stepSlot(self: *Service, index: usize) !void {
        const slot = &self.slots[index].?;
        const now_ns = now(self.io);
        if (slot.pending_id != null and now_ns - slot.pending_since_ns > request_timeout_ns) return error.RequestTimeout;
        if (now_ns - slot.last_announce_ns >= announce_interval_ns) try self.announce(slot);
        const message = slot.connection.receive(0) catch |err| {
            if (err == error.NoMessage) return;
            return err;
        };
        defer message.deinit(self.allocator);
        switch (message.code) {
            2 => try slot.connection.send(3, &.{0xc0}),
            3 => {},
            eth.announce_code => try self.requestMissing(slot, message.body),
            eth.get_code => try self.respond(slot, message.body),
            eth.pooled_code => try self.admit(slot, message.body),
            else => return error.UnsupportedPeerMessage,
        }
    }

    /// Announce the next page and advance only after a successful send.
    fn announce(self: *Service, slot: *Slot) !void {
        var items: [eth.max_hashes]eth.Announcement = undefined;
        var count: usize = 0;
        var next: usize = slot.cursor;
        if (self.server.mutex) |mutex| try mutex.lock(self.io);
        {
            defer if (self.server.mutex) |mutex| mutex.unlock(self.io);
            const page = self.server.pool.peerPage(slot.cursor);
            next = page.next;
            count = page.count;
            if (count > 0) {
                const first_index = slot.cursor % self.server.pool.entries.items.len;
                for (page.transactions[0..count], 0..) |raw, i| {
                    const entry = self.server.pool.entries.items[(first_index + i) % self.server.pool.entries.items.len];
                    items[i] = .{ .tx_type = if (raw[0] >= 0xc0) 0 else raw[0], .size = @intCast(raw.len), .hash = entry.hash };
                }
            }
        }
        if (count != 0) {
            const encoded = try eth.encodeAnnouncements(self.allocator, items[0..count]);
            defer self.allocator.free(encoded);
            try slot.connection.send(eth.announce_code, encoded);
        }
        slot.cursor = next;
        slot.last_announce_ns = now(self.io);
    }

    /// Request only missing hashes and allow one outstanding request.
    fn requestMissing(self: *Service, slot: *Slot, body: []const u8) !void {
        const announced = try eth.decodeAnnouncements(self.allocator, body);
        defer self.allocator.free(announced);
        if (slot.pending_id != null) return;
        slot.request_id +%= 1;
        var request: eth.Request = .{ .id = slot.request_id };
        if (self.server.mutex) |mutex| try mutex.lock(self.io);
        {
            defer if (self.server.mutex) |mutex| mutex.unlock(self.io);
            for (announced) |item| {
                if (self.server.pool.get(item.hash) != null) continue;
                var repeated = false;
                for (request.hashes[0..request.count]) |hash| {
                    if (std.mem.eql(u8, &hash, &item.hash)) {
                        repeated = true;
                        break;
                    }
                }
                if (repeated) continue;
                request.hashes[request.count] = item.hash;
                request.count += 1;
            }
        }
        if (request.count == 0) return;
        const encoded = try eth.encodeRequest(self.allocator, request);
        defer self.allocator.free(encoded);
        try slot.connection.send(eth.get_code, encoded);
        slot.pending_id = request.id;
        slot.pending_since_ns = now(self.io);
        slot.pending_count = request.count;
        @memcpy(slot.pending_hashes[0..request.count], request.hashes[0..request.count]);
    }

    /// Serve current pool entries within the 3 MiB transaction byte budget.
    fn respond(self: *Service, slot: *Slot, body: []const u8) !void {
        const request = try eth.decodeRequest(self.allocator, body);
        var response: eth.Response = .{ .id = request.id };
        var bytes: usize = 0;
        if (self.server.mutex) |mutex| try mutex.lock(self.io);
        const encoded = blk: {
            defer if (self.server.mutex) |mutex| mutex.unlock(self.io);
            for (request.hashes[0..request.count]) |hash| {
                const entry = self.server.pool.get(hash) orelse continue;
                const raw = entry.sidecar orelse entry.raw;
                if (raw.len > execution.pool.max_peer_page_bytes - bytes) break;
                response.transactions[response.count] = raw;
                response.count += 1;
                bytes += raw.len;
            }
            break :blk try eth.encodeResponse(self.allocator, response);
        };
        defer self.allocator.free(encoded);
        try slot.connection.send(eth.pooled_code, encoded);
    }

    /// Admit a matching bounded response through the public RPC pool path.
    fn admit(self: *Service, slot: *Slot, body: []const u8) !void {
        const response = try eth.decodeResponse(self.allocator, body);
        if (slot.pending_id == null or response.id != slot.pending_id.?) return error.UnsolicitedResponse;
        slot.pending_id = null;
        var bytes: usize = 0;
        for (response.transactions[0..response.count]) |raw| {
            bytes = try std.math.add(usize, bytes, raw.len);
            if (bytes > execution.pool.max_peer_page_bytes) return error.PeerMessageTooLarge;
            const canonical = if (raw[0] == 3) execution.kzg.canonicalTransaction(self.allocator, self.server.settings orelse return error.KzgUnavailable, raw) catch {
                slot.invalid +|= 1;
                if (slot.invalid >= max_invalid) return error.InvalidPeerTransactions;
                continue;
            } else try self.allocator.dupe(u8, raw);
            defer self.allocator.free(canonical);
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(canonical, &hash, .{});
            var requested = false;
            for (slot.pending_hashes[0..slot.pending_count]) |expected| {
                if (std.mem.eql(u8, &expected, &hash)) {
                    requested = true;
                    break;
                }
            }
            if (!requested) return error.UnrequestedTransaction;
            const result = try self.server.admitPeerTransaction(raw);
            if (result == .invalid) {
                slot.invalid +|= 1;
                if (slot.invalid >= max_invalid) return error.InvalidPeerTransactions;
            }
        }
    }

    /// Snapshot local chain status under the shared execution lock.
    fn localStatus(self: *Service) !eth.Status {
        if (self.server.mutex) |mutex| try mutex.lock(self.io);
        defer if (self.server.mutex) |mutex| mutex.unlock(self.io);
        const head = self.server.chain.latest();
        return .{ .network_id = @intCast(self.server.chain.chain_id), .genesis = self.genesis_hash, .fork_hash = self.fork_hash, .next_fork = 0, .earliest = 0, .latest = head.header.number, .head = head.hash };
    }

    /// Return the first vacant slot under the active peer cap.
    fn freeSlot(self: *const Service) ?usize {
        for (self.slots, 0..) |slot, i| if (slot == null) return i;
        return null;
    }

    /// Return a vacant worker slot under the pending-handshake cap.
    fn freePending(self: *const Service) ?usize {
        for (self.pending, 0..) |task, i| if (task == null) return i;
        return null;
    }

    /// Count active and pending connections before accepting more work.
    fn reservedCount(self: *const Service) usize {
        var count: usize = 0;
        for (self.slots) |slot| if (slot != null) {
            count += 1;
        };
        for (self.pending) |task| if (task != null) {
            count += 1;
        };
        return count;
    }

    /// Check whether an authenticated node ID already owns a slot.
    fn hasPeer(self: *const Service, id: [32]u8) bool {
        for (self.slots) |slot| {
            if (slot) |active| if (std.mem.eql(u8, &active.id, &id)) return true;
        }
        return false;
    }

    /// Close a failed session so discovery can retry it.
    fn drop(self: *Service, index: usize) void {
        if (self.slots[index]) |*slot| slot.connection.deinit();
        self.slots[index] = null;
    }
};

/// Hash an authenticated RLPx public key into its devp2p node ID.
fn nodeId(public: Ecdsa.PublicKey) [32]u8 {
    const encoded = public.toUncompressedSec1();
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(encoded[1..], &result, .{});
    return result;
}

/// Return monotonic nanoseconds for session deadlines and rotation intervals.
fn now(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

/// Reject special and unrelated internal addresses before a TCP dial.
fn safeEndpoint(local: [4]u8, remote: [4]u8) bool {
    if (remote[0] == 0 or remote[0] >= 224 or remote[0] == 169 and remote[1] == 254 or remote[0] == 100 and remote[1] >= 64 and remote[1] < 128) return false;
    if (remote[0] == 192 and remote[1] == 0 and (remote[2] == 0 or remote[2] == 2)) return false;
    if (remote[0] == 198 and (remote[1] == 18 or remote[1] == 19 or remote[1] == 51 and remote[2] == 100)) return false;
    if (remote[0] == 203 and remote[1] == 0 and remote[2] == 113) return false;
    if (remote[0] == 127) return local[0] == 127 and remote[1] == 0 and remote[2] == 0 and remote[3] != 0;
    const private_remote = remote[0] == 10 or remote[0] == 172 and remote[1] >= 16 and remote[1] <= 31 or remote[0] == 192 and remote[1] == 168;
    if (!private_remote) return true;
    return remote[0] == local[0] and remote[1] == local[1] and remote[2] == local[2];
}

/// Load or create one persistent secp256k1 key in the execution data directory.
pub fn loadIdentity(a: std.mem.Allocator, io: std.Io, data_dir: []const u8) !Ecdsa.KeyPair {
    const dir = try std.Io.Dir.cwd().openDir(io, data_dir, .{});
    defer dir.close(io);
    const raw = dir.readFileAlloc(io, "execution-node-key", a, .limited(33)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (raw) |bytes| {
        defer a.free(bytes);
        if (bytes.len != 32) return error.InvalidExecutionNodeKey;
        return Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(bytes[0..32].*));
    }
    const key = Ecdsa.KeyPair.generate(io);
    var file = try dir.createFile(io, "execution-node-key", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, &key.secret_key.bytes);
    try file.sync(io);
    return key;
}

test "execution discovery rejects unrelated internal and special addresses" {
    try std.testing.expect(safeEndpoint(.{ 127, 0, 0, 1 }, .{ 127, 0, 0, 2 }));
    try std.testing.expect(!safeEndpoint(.{ 8, 8, 8, 8 }, .{ 127, 0, 0, 1 }));
    try std.testing.expect(!safeEndpoint(.{ 8, 8, 8, 8 }, .{ 10, 0, 0, 1 }));
    try std.testing.expect(!safeEndpoint(.{ 8, 8, 8, 8 }, .{ 169, 254, 1, 1 }));
    try std.testing.expect(!safeEndpoint(.{ 8, 8, 8, 8 }, .{ 192, 0, 2, 1 }));
    try std.testing.expect(!safeEndpoint(.{ 192, 168, 1, 2 }, .{ 192, 168, 2, 2 }));
    try std.testing.expect(safeEndpoint(.{ 192, 168, 1, 2 }, .{ 192, 168, 1, 3 }));
    try std.testing.expect(safeEndpoint(.{ 8, 8, 8, 8 }, .{ 1, 1, 1, 1 }));
}
