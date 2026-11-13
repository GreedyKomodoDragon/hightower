// A loopback Engine API fixture anchors an Osaka execution state. An optional
// pinned genesis loads the same accounts and header as Geth so payloads can be
// built here and validated there; canonical history remains in memory.
const std = @import("std");
const execution = @import("execution");
const engine = @import("engine_server");

/// Starts a local authenticated Engine API fixture and prints its genesis hash.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3 and args.len != 4 and !(args.len == 5 and std.mem.eql(u8, args[3], "--fixture-hashes"))) return error.ExpectedPortJwtFileAndOptionalGenesis;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const raw = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], a, .limited(128));
    const trimmed = std.mem.trim(u8, raw, " \r\n\t");
    if (trimmed.len != 64) return error.InvalidJwtSecret;
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, trimmed);
    var world = execution.state.State.init(a);
    defer world.deinit();
    const has_genesis = args.len == 4;
    var header = if (has_genesis) (try execution.genesis.load(a, init.io, args[3], &world)).header else std.mem.zeroes(execution.Header);
    if (!has_genesis) {
        header.state_root = try world.stateRoot();
        header.gas_limit = 30_000_000;
        header.base_fee_per_gas = 1;
    }
    if (has_genesis) {
        // SAFETY: hexToBytes fills the pinned hash or startup fails.
        var expected: execution.Hash = undefined;
        _ = try std.fmt.hexToBytes(&expected, "d5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f");
        if (!std.mem.eql(u8, &(try execution.transition.headerHash(a, .osaka, header)), &expected)) return error.GenesisHashMismatch;
    }
    var chain = try execution.chain.Chain.init(a, if (has_genesis) 1337 else 1, .osaka, header, &world);
    defer chain.deinit();
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var server: engine.Server = .{ .allocator = a, .chain = &chain, .world = &world, .pool = &pool, .settings = &settings, .secret = secret };
    if (args.len == 5) {
        const hashes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[4], a, .limited(1024));
        var lines = std.mem.tokenizeScalar(u8, hashes, '\n');
        const allowed = try a.alloc(execution.Hash, 3);
        for (allowed) |*hash| {
            const line = lines.next() orelse return error.InvalidFixtureHashes;
            if (line.len != 64) return error.InvalidFixtureHashes;
            _ = std.fmt.hexToBytes(hash, line) catch return error.InvalidFixtureHashes;
        }
        if (lines.next() != null) return error.InvalidFixtureHashes;
        server.fixture_payload_hashes = allowed;
    }
    defer server.deinit();
    const hash = chain.latest().hash;
    const output = try std.fmt.allocPrint(a, "0x{s}\n", .{std.fmt.bytesToHex(hash, .lower)});
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    var listener = try address.listen(init.io, .{ .reuse_address = true });
    defer listener.deinit(init.io);
    try server.serve(a, init.io, &listener);
}
