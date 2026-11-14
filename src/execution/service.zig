// An Osaka genesis anchors one durable execution chain. Engine fork choice
// commits canonical state, and public RPC reads that same state under a lock.
// Finalized receipts are streamed before pruning advances the history floor.
//
// genesis -> recovery -> transfer catch-up -> Engine + public RPC
const std = @import("std");
const execution = @import("execution");
const engine = @import("engine_server");

const Config = struct {
    genesis: []const u8,
    data_dir: []const u8,
    jwt_secret: []const u8,
    trusted_setup: []const u8,
    engine_bind: []const u8,
    rpc_bind: []const u8,
    transfer_contract: ?[]const u8 = null,
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
fn parseConfig(a: std.mem.Allocator, bytes: []const u8) !struct { value: Config, engine_address: std.Io.net.IpAddress, rpc_address: std.Io.net.IpAddress } {
    const parsed = try std.json.parseFromSlice(Config, a, bytes, .{ .allocate = .alloc_always });
    const config = parsed.value;
    if (config.genesis.len == 0 or config.data_dir.len == 0 or config.jwt_secret.len == 0 or config.trusted_setup.len == 0) return error.MissingConfig;
    const engine_address = try bindAddress(config.engine_bind);
    const rpc_address = try bindAddress(config.rpc_bind);
    if (std.mem.eql(u8, config.engine_bind, config.rpc_bind)) return error.DuplicateBindAddress;
    return .{ .value = config, .engine_address = engine_address, .rpc_address = rpc_address };
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
    var store = try execution.durable.Store.open(a, init.io, std.Io.Dir.cwd(), config.data_dir, .osaka, genesis.header, &world);
    defer store.close();
    try store.checkIdentity(genesis.chain_id, .osaka);
    var chain = try execution.chain.Chain.init(a, genesis.chain_id, .osaka, genesis.header, &world);
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
    var rpc_server: execution.rpc.Server = .{ .chain = &chain, .pool = &pool, .world = &world, .settings = &settings, .mutex = &mutex };
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
    _ = try parseConfig(a, valid);
}
