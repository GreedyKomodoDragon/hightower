// An Osaka genesis anchors one durable execution chain. Engine fork choice
// commits canonical state, and public RPC reads that same state under a lock.
// Finalized receipts are streamed before pruning advances the history floor.
//
// genesis -> recovery -> transfer catch-up -> Engine + public RPC
const std = @import("std");
const execution = @import("execution");
const engine = @import("engine_server");
const peer_gossip = @import("peer_gossip");

const Config = struct {
    genesis: []const u8,
    checkpoint_header: ?[]const u8 = null,
    checkpoint_state: ?[]const u8 = null,
    checkpoint_hash: ?[]const u8 = null,
    data_dir: []const u8,
    jwt_secret: []const u8,
    trusted_setup: []const u8,
    engine_bind: []const u8,
    rpc_bind: []const u8,
    execution_p2p_bind: ?[]const u8 = null,
    execution_advertise_ip: ?[]const u8 = null,
    execution_bootnodes: []const []const u8 = &.{},
    transfer_contract: ?[]const u8 = null,
    archive: bool = false,
    retained_canonical_blocks: u64 = execution.durable.default_retained_canonical_blocks,
};

/// Parses a required IPv4 host:port listener address.
fn bindAddress(value: []const u8) !std.Io.net.IpAddress {
    const separator = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidBindAddress;
    if (separator == 0 or separator + 1 == value.len) return error.InvalidBindAddress;
    const port = try std.fmt.parseInt(u16, value[separator + 1 ..], 10);
    if (port == 0) return error.InvalidBindAddress;
    return std.Io.net.IpAddress.parseIp4(value[0..separator], port);
}

/// Validates production paths and bind addresses before opening storage.
fn parseConfig(a: std.mem.Allocator, bytes: []const u8) !struct { value: Config, engine_address: std.Io.net.IpAddress, rpc_address: std.Io.net.IpAddress, peer_address: ?std.Io.net.IpAddress, advertised_ip: ?[4]u8 } {
    const parsed = try std.json.parseFromSlice(Config, a, bytes, .{ .allocate = .alloc_always });
    const config = parsed.value;
    if (config.genesis.len == 0 or config.data_dir.len == 0 or config.jwt_secret.len == 0 or config.trusted_setup.len == 0) return error.MissingConfig;
    if (config.checkpoint_header != null or config.checkpoint_state != null or config.checkpoint_hash != null) {
        if (config.checkpoint_header == null or config.checkpoint_state == null or config.checkpoint_hash == null) return error.MissingCheckpoint;
        if (config.checkpoint_header.?.len == 0 or config.checkpoint_state.?.len == 0 or config.checkpoint_hash.?.len != 66 or !std.mem.startsWith(u8, config.checkpoint_hash.?, "0x")) return error.InvalidCheckpoint;
        var hash: execution.Hash = .{0} ** 32;
        _ = std.fmt.hexToBytes(&hash, config.checkpoint_hash.?[2..]) catch return error.InvalidCheckpoint;
    }
    const engine_address = try bindAddress(config.engine_bind);
    const rpc_address = try bindAddress(config.rpc_bind);
    if (std.mem.eql(u8, config.engine_bind, config.rpc_bind)) return error.DuplicateBindAddress;
    var peer_address: ?std.Io.net.IpAddress = null;
    var advertised_ip: ?[4]u8 = null;
    if (config.execution_p2p_bind) |bind| {
        const address = try bindAddress(bind);
        if (std.mem.eql(u8, bind, config.rpc_bind) or std.mem.eql(u8, bind, config.engine_bind)) return error.DuplicateBindAddress;
        peer_address = address;
        advertised_ip = if (config.execution_advertise_ip) |ip| (try std.Io.net.IpAddress.parseIp4(ip, 1)).ip4.bytes else address.ip4.bytes;
        if (advertised_ip.?[0] == 0) return error.InvalidAdvertisedAddress;
    } else {
        if (config.execution_bootnodes.len != 0 or config.execution_advertise_ip != null) return error.MissingExecutionPeerBind;
    }
    return .{ .value = config, .engine_address = engine_address, .rpc_address = rpc_address, .peer_address = peer_address, .advertised_ip = advertised_ip };
}

/// Writes one complete JSON line to stdout for the finalized stream.
fn writeOutput(context: *anyopaque, line: []const u8) anyerror!void {
    const io: *std.Io = @ptrCast(@alignCast(context));
    try std.Io.File.stdout().writeStreamingAll(io.*, line);
}

const EngineTask = struct {
    server: *engine.Server,
    io: std.Io,
    listener: *std.Io.net.Server,

    /// Accepts authenticated Engine requests on the service's second listener.
    fn run(self: *EngineTask) void {
        self.server.serve(std.heap.page_allocator, self.io, self.listener) catch |err| std.log.err("Engine listener stopped: {s}", .{@errorName(err)});
    }
};

/// Starts a recovered execution service from a required JSON configuration.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--config")) return error.ExpectedConfigPath;
    const raw_config = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], a, .limited(64 * 1024));
    const parsed = try parseConfig(a, raw_config);
    const config = parsed.value;
    const raw_secret = try std.Io.Dir.cwd().readFileAlloc(init.io, config.jwt_secret, a, .limited(128));
    const secret_hex = std.mem.trim(u8, raw_secret, " \r\n\t");
    if (secret_hex.len != 64) return error.InvalidJwtSecret;
    var secret: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret, secret_hex) catch return error.InvalidJwtSecret;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const genesis = try execution.genesis.load(a, init.io, config.genesis, &world);
    var anchor = genesis.header;
    if (config.checkpoint_header) |path| {
        var trusted_hash: execution.Hash = .{0} ** 32;
        _ = std.fmt.hexToBytes(&trusted_hash, config.checkpoint_hash.?[2..]) catch return error.InvalidCheckpoint;
        anchor = try execution.checkpoint.load(a, init.io, path, config.checkpoint_state.?, trusted_hash, &world);
    }
    var store = try execution.durable.Store.open(a, init.io, std.Io.Dir.cwd(), config.data_dir, .osaka, anchor, &world);
    store.archive = config.archive;
    store.retained_canonical_blocks = config.retained_canonical_blocks;
    defer store.close();
    try store.checkIdentity(genesis.chain_id, .osaka);
    var chain = try execution.chain.Chain.init(a, genesis.chain_id, .osaka, anchor, &world);
    defer chain.deinit();
    try store.recover(&chain, &world);
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    var settings = try execution.kzg.loadTrustedSetup(try a.dupeZ(u8, config.trusted_setup));
    defer settings.deinit();
    var mutex: std.Io.Mutex = .init;
    // SAFETY: The stream is initialized before its pointer is used.
    var stream: execution.transfers.Stream = undefined;
    var transfers: ?*execution.transfers.Stream = null;
    var io = init.io;
    if (config.transfer_contract) |address| {
        if (address.len != 42 or !std.mem.startsWith(u8, address, "0x")) return error.InvalidTransferContract;
        // SAFETY: hexToBytes fills the address or startup fails.
        var contract: execution.Address = undefined;
        _ = std.fmt.hexToBytes(&contract, address[2..]) catch return error.InvalidTransferContract;
        stream = .{ .allocator = a, .store = &store, .chain = &chain, .contract = contract, .output = writeOutput, .context = &io };
        try stream.catchUp();
        transfers = &stream;
    }
    var engine_server: engine.Server = .{ .allocator = a, .chain = &chain, .world = &world, .pool = &pool, .settings = &settings, .store = &store, .transfers = transfers, .mutex = &mutex, .secret = secret };
    defer engine_server.deinit();
    var sync_progress: execution.rpc.SyncProgress = .{};
    engine_server.sync_progress = &sync_progress;
    var rpc_server: execution.rpc.Server = .{ .chain = &chain, .pool = &pool, .world = &world, .store = &store, .settings = &settings, .mutex = &mutex, .payload_build_ns = &engine_server.payload_build_ns, .sync_progress = &sync_progress };
    rpc_server.io = init.io;
    var gossip: ?peer_gossip.Service = null;
    if (parsed.peer_address) |peer_address| {
        const identity = try peer_gossip.loadIdentity(std.heap.page_allocator, init.io, config.data_dir);
        const genesis_hash = try execution.transition.headerHash(a, .osaka, genesis.header);
        gossip = try peer_gossip.Service.init(std.heap.page_allocator, init.io, &rpc_server, identity, peer_address, parsed.advertised_ip.?, config.execution_bootnodes, genesis_hash);
        try gossip.?.start();
    }
    var engine_listener = try parsed.engine_address.listen(init.io, .{ .reuse_address = true });
    defer engine_listener.deinit(init.io);
    var rpc_listener = try parsed.rpc_address.listen(init.io, .{ .reuse_address = true });
    defer rpc_listener.deinit(init.io);
    var task = EngineTask{ .server = &engine_server, .io = init.io, .listener = &engine_listener };
    const thread = try std.Thread.spawn(.{}, EngineTask.run, .{&task});
    thread.detach();
    try rpc_server.serve(std.heap.page_allocator, init.io, &rpc_listener);
}

test "service config validates separate IPv4 listeners" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const valid = try std.json.Stringify.valueAlloc(a, Config{ .genesis = "g", .data_dir = "d", .jwt_secret = "j", .trusted_setup = "k", .engine_bind = "127.0.0.1:18551", .rpc_bind = "127.0.0.1:18545" }, .{});
    defer a.free(valid);
    const default_config = (try parseConfig(a, valid)).value;
    try std.testing.expect(!default_config.archive);
    try std.testing.expectEqual(execution.durable.default_retained_canonical_blocks, default_config.retained_canonical_blocks);
    const peer_config_json = try std.json.Stringify.valueAlloc(a, Config{ .genesis = "g", .data_dir = "d", .jwt_secret = "j", .trusted_setup = "k", .engine_bind = "127.0.0.1:18551", .rpc_bind = "127.0.0.1:18545", .execution_p2p_bind = "127.0.0.1:18546" }, .{});
    const peer_config = try parseConfig(a, peer_config_json);
    try std.testing.expectEqual(@as(u16, 18546), peer_config.peer_address.?.ip4.port);
    const duplicate_peer_bind = try std.json.Stringify.valueAlloc(a, Config{ .genesis = "g", .data_dir = "d", .jwt_secret = "j", .trusted_setup = "k", .engine_bind = "127.0.0.1:18551", .rpc_bind = "127.0.0.1:18545", .execution_p2p_bind = "127.0.0.1:18545" }, .{});
    try std.testing.expectError(error.DuplicateBindAddress, parseConfig(a, duplicate_peer_bind));
    const missing_peer_bind = try std.json.Stringify.valueAlloc(a, Config{ .genesis = "g", .data_dir = "d", .jwt_secret = "j", .trusted_setup = "k", .engine_bind = "127.0.0.1:18551", .rpc_bind = "127.0.0.1:18545", .execution_bootnodes = &.{"enr:example"} }, .{});
    try std.testing.expectError(error.MissingExecutionPeerBind, parseConfig(a, missing_peer_bind));
    const configured = try std.json.Stringify.valueAlloc(a, Config{ .genesis = "g", .data_dir = "d", .jwt_secret = "j", .trusted_setup = "k", .engine_bind = "127.0.0.1:18551", .rpc_bind = "127.0.0.1:18545", .archive = true, .retained_canonical_blocks = 512 }, .{});
    const configured_value = (try parseConfig(a, configured)).value;
    try std.testing.expect(configured_value.archive);
    try std.testing.expectEqual(@as(u64, 512), configured_value.retained_canonical_blocks);
    const partial = try std.json.Stringify.valueAlloc(a, Config{ .genesis = "g", .checkpoint_header = "header.rlp", .data_dir = "d", .jwt_secret = "j", .trusted_setup = "k", .engine_bind = "127.0.0.1:18551", .rpc_bind = "127.0.0.1:18545" }, .{});
    try std.testing.expectError(error.MissingCheckpoint, parseConfig(a, partial));
    const invalid = try std.json.Stringify.valueAlloc(a, Config{ .genesis = "g", .checkpoint_header = "header.rlp", .checkpoint_state = "state.bin", .checkpoint_hash = "0xnot-a-hash", .data_dir = "d", .jwt_secret = "j", .trusted_setup = "k", .engine_bind = "127.0.0.1:18551", .rpc_bind = "127.0.0.1:18545" }, .{});
    try std.testing.expectError(error.InvalidCheckpoint, parseConfig(a, invalid));
}

test {
    _ = peer_gossip;
}
