// A trusted Fulu anchor fixes the initial fork-choice state. Ordered peer
// blocks pass column, execution, and state checks before the head is saved.
//
//   anchor/snapshot -> peer range -> verified block -> durable head
// The runtime has one active peer and one configured bootstrap ENR.
const std = @import("std");
const hightower = @import("hightower");
const ssz = @import("ssz");
const merkle = @import("merkle");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

comptime {
    _ = @sizeOf(hightower.fulu.BeaconState);
    _ = hightower.consensus.stateTransition;
}

const version = "0.0.0";
const Config = struct {
    listen_address: []const u8,
    anchor_state: []const u8 = "",
    anchor_block: []const u8 = "",
    bootstrap_enr: []const u8 = "",
    data_dir: []const u8 = "",
    trusted_setup: []const u8 = "",
    engine_url: []const u8 = "",
};
const ParsedConfig = struct { address: std.Io.net.IpAddress, config: Config };

/// Validate the required config before allocating runtime services or binding a socket.
fn parseConfig(allocator: std.mem.Allocator, bytes: []const u8) !ParsedConfig {
    const parsed = try std.json.parseFromSlice(Config, allocator, bytes, .{ .allocate = .alloc_always });
    // The caller's arena owns decoded strings for the lifetime of the node.
    const value = parsed.value;
    const separator = std.mem.lastIndexOfScalar(u8, value.listen_address, ':') orelse return error.InvalidListenAddress;
    if (separator == 0 or separator + 1 == value.listen_address.len) return error.InvalidListenAddress;
    const port = try std.fmt.parseInt(u16, value.listen_address[separator + 1 ..], 10);
    if (port == 0) return error.InvalidListenAddress;
    if (value.anchor_state.len != 0) {
        if (value.anchor_block.len == 0 or value.data_dir.len == 0 or value.trusted_setup.len == 0 or value.engine_url.len == 0) return error.MissingConfig;
    } else if (value.anchor_block.len != 0 or value.bootstrap_enr.len != 0 or value.data_dir.len != 0 or value.trusted_setup.len != 0 or value.engine_url.len != 0) {
        return error.MissingConfig;
    }
    return .{ .address = try std.Io.net.IpAddress.parseIp4(value.listen_address[0..separator], port), .config = value };
}

/// Decode one required 32-byte environment credential without exposing its value.
fn decodeSecret(value: ?[]const u8) ![32]u8 {
    const hex = value orelse return error.MissingSecret;
    if (hex.len != 64) return error.InvalidSecret;
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch return error.InvalidSecret;
    return bytes;
}

/// Read and validate a bounded JSON config file.
fn loadConfig(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !ParsedConfig {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
    defer allocator.free(bytes);
    return parseConfig(allocator, bytes);
}

/// Give mainnet SSZ state decoding enough stack space on supported hosts.
pub fn main(init: std.process.Init) !void {
    var task = RuntimeTask{ .init = init };
    const thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 * 1024 }, RuntimeTask.run, .{&task});
    thread.join();
    if (task.failure) |err| return err;
}

const RuntimeTask = struct {
    init: std.process.Init,
    failure: ?anyerror = null,

    /// Retain startup errors for the process entry point.
    fn run(self: *RuntimeTask) void {
        runRuntime(self.init) catch |err| {
            self.failure = err;
        };
    }
};

/// Start the configured Beacon API, P2P service, and durable peer importer.
fn runRuntime(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
        try std.Io.File.stdout().writeStreamingAll(init.io, "Usage: hightower --config <path>\n");
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--version")) {
        try std.Io.File.stdout().writeStreamingAll(init.io, "hightower " ++ version ++ "\n");
        return;
    }
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--config")) return error.ExpectedConfigPath;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const config = try loadConfig(init.io, arena.allocator(), args[2]);
    const settings = config.config;
    if (settings.anchor_state.len == 0) {
        try serveBundledAnchor(allocator, init.io, config.address);
        return;
    }
    const seed = decodeSecret(init.environ_map.get("HIGHTOWER_NODE_KEY")) catch |err| switch (err) {
        error.MissingSecret => return error.MissingNodeKey,
        else => return error.InvalidNodeKey,
    };
    const key = try Ecdsa.KeyPair.generateDeterministic(seed);
    const jwt = decodeSecret(init.environ_map.get("HIGHTOWER_ENGINE_JWT_SECRET")) catch |err| switch (err) {
        error.MissingSecret => return error.MissingEngineJwtSecret,
        else => return error.InvalidEngineJwtSecret,
    };
    const state_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, settings.anchor_state, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(state_bytes);
    var state_reader: std.Io.Reader = .fixed(state_bytes);
    const state = try ssz.deserialize(allocator, hightower.fulu.BeaconState, &state_reader);
    defer ssz.freeDecoded(allocator, hightower.fulu.BeaconState, state);
    const block_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, settings.anchor_block, allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, hightower.fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, hightower.fulu.BeaconBlock, block);
    try std.Io.Dir.cwd().createDirPath(init.io, settings.data_dir);
    const dir = try std.Io.Dir.cwd().openDir(init.io, settings.data_dir, .{ .iterate = true });
    defer dir.close(init.io);
    var store = hightower.consensus.loadForkChoiceStore(allocator, init.io, dir, "fork-choice.bin") catch |err| switch (err) {
        error.FileNotFound => try hightower.consensus.initForkChoiceStore(allocator, &state, &block),
        else => return err,
    };
    defer store.deinit();
    const anchor_root = try merkle.HashTreeRoot(allocator, block);
    if (store.genesis_time != state.genesis_time or !store.blocks.contains(anchor_root)) return error.WrongAnchor;
    const ingress = hightower.consensus.P2PIngress.Config{ .genesis_validators_root = state.genesis_validators_root, .fulu_version = state.fork.current_version, .fulu_epoch = 0, .blob_schedule = &hightower.consensus.BLOB_SCHEDULE };
    const digest = try ingress.digestAtSlot(block.slot);
    var kzg = try hightower.execution.kzg.loadTrustedSetup(try arena.allocator().dupeZ(u8, settings.trusted_setup));
    defer kzg.deinit();
    var engine = try hightower.engine_client.Client.init(allocator, init.io, settings.engine_url, jwt, .osaka);
    defer engine.deinit();
    const identity = try nodeId(allocator, key);
    var columns = try hightower.consensus.DataColumns.Store.open(allocator, init.io, dir, "columns", state.genesis_validators_root, identity, 128);
    defer columns.deinit();
    const head = try hightower.consensus.getForkChoiceHead(&store);
    var coordinator = hightower.consensus.PeerSync.Coordinator{ .allocator = allocator, .io = init.io, .dir = dir, .store = &store, .columns = &columns, .settings = &kzg, .engine = engine.interface(), .head = head, .next_slot = try std.math.add(u64, store.blocks.get(head).?.slot, 1) };
    var mutex: std.Io.Mutex = .init;
    var announcements = Announcements{ .coordinator = &coordinator, .mutex = &mutex, .slot = store.blocks.get(head).?.slot };
    var gossip = try hightower.consensus.P2PGossip.Service.init(allocator, ingress, digest, &.{}, 1, 3, .{ .context = &announcements, .validate = Announcements.block }, .{ .context = &announcements, .validate = Announcements.attestation }, .{ .context = &announcements, .validate = Announcements.aggregate }, null);
    defer gossip.deinit();
    var fork_id = [_]u8{0} ** 16;
    @memcpy(fork_id[0..4], &digest);
    const local = hightower.consensus.ENR.Local{ .sequence = try nextEnrSequence(allocator, init.io, dir), .ip = config.address.ip4.bytes, .udp_port = 0, .tcp_port = 0, .fork_id = fork_id, .next_fork_digest = .{0} ** 4, .custody_group_count = 128 };
    const status = hightower.consensus.P2PControl.Status{ .fork_digest = digest, .finalized_root = store.finalized_checkpoint.root, .finalized_epoch = store.finalized_checkpoint.epoch, .head_root = head, .head_slot = store.blocks.get(head).?.slot, .earliest_available_slot = block.slot };
    const metadata = hightower.consensus.P2PControl.MetaData{ .seq_number = 1, .attnets = .{ .data = [_]bool{false} ** 64 }, .syncnets = .{ .data = [_]bool{false} ** 4 }, .custody_group_count = 128 };
    var p2p = try hightower.consensus.P2PService.Service.init(allocator, init.io, key, local, 2, &gossip, status, metadata);
    defer p2p.deinit();
    if (settings.bootstrap_enr.len != 0) try p2p.addBootstrap(settings.bootstrap_enr);
    p2p.setRoutes(.{ .blocks = .{ .context = &coordinator, .by_root = hightower.consensus.PeerSync.Coordinator.byRoot, .root_at_slot = hightower.consensus.PeerSync.Coordinator.atSlot }, .columns = &columns, .canonical = .{ .context = &coordinator, .root_at_slot = hightower.consensus.PeerSync.Coordinator.atSlot } });
    const uri = try p2p.localUri();
    defer allocator.free(uri);
    std.log.info("local ENR: {s}", .{uri});
    var listener = try config.address.listen(init.io, .{ .reuse_address = true });
    defer listener.deinit(init.io);
    var api = Api{ .allocator = allocator, .io = init.io, .listener = &listener, .store = &store, .mutex = &mutex, .version = state.fork.current_version };
    const thread = try std.Thread.spawn(.{}, Api.run, .{&api});
    thread.detach();
    while (true) {
        try p2p.step(100);
        if (!p2p.connected()) continue;
        const advertised = @max(p2p.connection.?.remote_status.head_slot, announcements.slot);
        if (advertised < coordinator.next_slot) continue;
        const active = try p2p.activePeer();
        try mutex.lock(init.io);
        announcements.importing = true;
        const result = coordinator.step(active, @min(advertised - coordinator.next_slot + 1, 16));
        announcements.importing = false;
        mutex.unlock(init.io);
        _ = result catch |err| {
            if (err == error.ForkchoiceUpdateFailed or err == error.ImportCommitFailed) return err;
            std.log.warn("peer import stopped at last valid head: {s}", .{@errorName(err)});
            switch (err) {
                error.InvalidStateRoot, error.InvalidResponseOrder, error.ConflictingParent, error.DuplicateBlock, error.UnrequestedBlock, error.InvalidCellProof, error.InvalidDataColumn => gossip.peers.noteInvalid(p2p.connection.?.connection.peer_id),
                else => {},
            }
            p2p.connection.?.deinit();
            p2p.connection = null;
            continue;
        };
        p2p.status.head_root = coordinator.head;
        p2p.status.head_slot = store.blocks.get(coordinator.head).?.slot;
    }
}

/// Keep the original read-only fixture mode for existing minimal configs.
fn serveBundledAnchor(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) !void {
    const fixtures = hightower.consensus.fixtureRunner;
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, hightower.fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const block = try ssz.deserialize(allocator, hightower.fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, hightower.fulu.BeaconBlock, block);
    var store = try hightower.consensus.initForkChoiceStore(allocator, &state, &block);
    defer store.deinit();
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    try hightower.api.serve(allocator, io, &listener, &store, .{ .genesis_fork_version = .{ 0, 0, 0, 0 } });
}

const Api = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: *std.Io.net.Server,
    store: *const hightower.consensus.ForkChoiceStore,
    mutex: *std.Io.Mutex,
    version: [4]u8,
    /// Serve read-only requests against one locked fork-choice view.
    fn run(self: *Api) void {
        hightower.api.serveLocked(self.allocator, self.io, self.listener, self.store, .{ .genesis_fork_version = self.version }, self.mutex) catch |err| std.log.err("API stopped: {s}", .{@errorName(err)});
    }
};

const Announcements = struct {
    coordinator: *hightower.consensus.PeerSync.Coordinator,
    mutex: *std.Io.Mutex,
    slot: u64,
    importing: bool = false,
    /// Queue the highest announced slot for checked range import.
    fn block(context: *anyopaque, signed: *const hightower.fulu.SignedBeaconBlock) !void {
        const self: *Announcements = @ptrCast(@alignCast(context));
        self.slot = @max(self.slot, signed.message.slot);
    }
    /// Persist a checked attestation and its selected head.
    fn attestation(context: *anyopaque, value: *const hightower.fulu.Attestation) !void {
        const self: *Announcements = @ptrCast(@alignCast(context));
        if (!self.importing) try self.mutex.lock(self.coordinator.io);
        defer if (!self.importing) self.mutex.unlock(self.coordinator.io);
        try hightower.consensus.onForkChoiceAttestation(self.coordinator.store, value.*, false);
        self.coordinator.head = try hightower.consensus.getForkChoiceHead(self.coordinator.store);
        try hightower.consensus.saveForkChoiceStore(self.coordinator.allocator, self.coordinator.io, self.coordinator.dir, "fork-choice.bin", self.coordinator.store);
    }
    /// Apply an aggregate's attestation through the same gate.
    fn aggregate(context: *anyopaque, value: *const hightower.fulu.SignedAggregateAndProof) !void {
        return attestation(context, &value.message.aggregate);
    }
};

/// Derive the persistent custody identity from the configured node key.
fn nodeId(allocator: std.mem.Allocator, key: Ecdsa.KeyPair) ![32]u8 {
    const encoded = try hightower.consensus.ENR.encode(allocator, key, .{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 1, .tcp_port = 1, .fork_id = .{0} ** 16, .next_fork_digest = .{0} ** 4, .custody_group_count = 128 });
    defer allocator.free(encoded);
    return (try hightower.consensus.ENR.decode(allocator, encoded)).node_id;
}

/// Advance the signed ENR version before advertising freshly bound P2P ports.
fn nextEnrSequence(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !u64 {
    const previous = dir.readFileAlloc(io, "enr-sequence", allocator, .limited(32)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (previous) |bytes| allocator.free(bytes);
    const sequence = if (previous) |bytes| try std.math.add(u64, try std.fmt.parseInt(u64, bytes, 10), 1) else 1;
    const text = try std.fmt.allocPrint(allocator, "{d}", .{sequence});
    defer allocator.free(text);
    var atomic = try dir.createFileAtomic(io, "enr-sequence", .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, text);
    try atomic.file.sync(io);
    try atomic.replace(io);
    return sequence;
}

test "runtime config and environment credentials" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const value = Config{
        .listen_address = "127.0.0.1:5052",
        .anchor_state = "state.ssz",
        .anchor_block = "block.ssz",
        .bootstrap_enr = "",
        .data_dir = "data",
        .trusted_setup = "setup.txt",
        .engine_url = "http://127.0.0.1:8551",
    };
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(encoded);
    _ = try parseConfig(arena.allocator(), encoded);
    try std.testing.expectError(error.MissingSecret, decodeSecret(null));
    try std.testing.expectError(error.InvalidSecret, decodeSecret("short"));
    try std.testing.expectError(error.InvalidSecret, decodeSecret("zz00000000000000000000000000000000000000000000000000000000000000"));
    const seed = try decodeSecret("0000000000000000000000000000000000000000000000000000000000000001");
    try std.testing.expectEqual(try nodeId(std.testing.allocator, try Ecdsa.KeyPair.generateDeterministic(seed)), try nodeId(std.testing.allocator, try Ecdsa.KeyPair.generateDeterministic(seed)));
    const legacy = .{ .listen_address = "127.0.0.1:5052", .node_key = @as(?[]const u8, null) };
    const legacy_json = try std.json.Stringify.valueAlloc(std.testing.allocator, legacy, .{});
    defer std.testing.allocator.free(legacy_json);
    try std.testing.expectError(error.UnknownField, parseConfig(arena.allocator(), legacy_json));
    const legacy_jwt = .{ .listen_address = "127.0.0.1:5052", .engine_jwt_secret = @as(?[]const u8, null) };
    const jwt_json = try std.json.Stringify.valueAlloc(std.testing.allocator, legacy_jwt, .{});
    defer std.testing.allocator.free(jwt_json);
    try std.testing.expectError(error.UnknownField, parseConfig(arena.allocator(), jwt_json));
}

test "ENR sequence advances across restarts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(@as(u64, 1), try nextEnrSequence(std.testing.allocator, std.testing.io, tmp.dir));
    try std.testing.expectEqual(@as(u64, 2), try nextEnrSequence(std.testing.allocator, std.testing.io, tmp.dir));
}
