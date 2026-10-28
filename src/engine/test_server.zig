// A loopback Engine API fixture anchors an Osaka execution state. An optional
// pinned genesis loads the same accounts and header as Geth so payloads can be
// built here and validated there; canonical history remains in memory.
const std = @import("std");
const execution = @import("execution");
const engine = @import("engine_server");
const wire = @import("engine_wire");

/// Loads the pinned Osaka genesis accounts and header, checking Geth's block hash.
fn loadGenesis(a: std.mem.Allocator, io: std.Io, path: []const u8, world: *execution.state.State) !execution.Header {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(2 * 1024 * 1024));
    const parsed = try std.json.parseFromSlice(wire.Value, a, raw, .{});
    const root = parsed.value;
    const accounts = try wire.field(root, "alloc");
    if (accounts != .object) return error.InvalidGenesis;
    var it = accounts.object.iterator();
    while (it.next()) |entry| {
        var address: execution.Address = undefined;
        if (entry.key_ptr.*.len != 40) return error.InvalidGenesis;
        _ = try std.fmt.hexToBytes(&address, entry.key_ptr.*);
        const account = entry.value_ptr.*;
        try world.createAccount(address);
        if (account.object.get("balance")) |balance| try world.setBalance(address, try wire.quantity(u256, balance));
        if (account.object.get("nonce")) |nonce| try world.setNonce(address, try wire.quantity(u64, nonce));
        if (account.object.get("code")) |code| {
            const bytes = try wire.bytes(a, code, 1024 * 1024);
            _ = try world.setCode(address, bytes);
        }
    }
    const empty_root = try execution.trie.orderedRoot(a, &.{});
    var ommers: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&.{0xc0}, &ommers, .{});
    var requests: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&.{}, &requests, .{});
    var header = std.mem.zeroes(execution.Header);
    header.ommers_hash = ommers;
    header.state_root = try world.stateRoot();
    header.transactions_root = empty_root;
    header.receipts_root = empty_root;
    header.withdrawals_root = empty_root;
    header.requests_hash = requests;
    header.gas_limit = try wire.quantity(u64, try wire.field(root, "gasLimit"));
    header.base_fee_per_gas = try wire.quantity(u256, try wire.field(root, "baseFeePerGas"));
    header.timestamp = try wire.quantity(u64, try wire.field(root, "timestamp"));
    header.extra_data = try wire.bytes(a, try wire.field(root, "extraData"), 32);
    const hash = try execution.transition.headerHash(a, .osaka, header);
    const expected = try wire.fixed(32, .{ .string = "0xd5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f" });
    if (!std.mem.eql(u8, &hash, &expected)) return error.GenesisHashMismatch;
    return header;
}

/// Starts a local authenticated Engine API fixture and prints its genesis hash.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3 and args.len != 4) return error.ExpectedPortJwtFileAndOptionalGenesis;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const raw = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], a, .limited(128));
    const trimmed = std.mem.trim(u8, raw, " \r\n\t");
    if (trimmed.len != 64) return error.InvalidJwtSecret;
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, trimmed);
    var world = execution.state.State.init(a);
    defer world.deinit();
    var header = if (args.len == 4) try loadGenesis(a, init.io, args[3], &world) else std.mem.zeroes(execution.Header);
    if (args.len == 3) {
        header.state_root = try world.stateRoot();
        header.gas_limit = 30_000_000;
        header.base_fee_per_gas = 1;
    }
    var chain = try execution.chain.Chain.init(a, if (args.len == 4) 1337 else 1, .osaka, header, &world);
    defer chain.deinit();
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var server: engine.Server = .{ .allocator = a, .chain = &chain, .world = &world, .pool = &pool, .settings = &settings, .secret = secret };
    defer server.deinit();
    const hash = chain.latest().hash;
    const output = try std.fmt.allocPrint(a, "0x{s}\n", .{std.fmt.bytesToHex(hash, .lower)});
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    var listener = try address.listen(init.io, .{ .reuse_address = true });
    defer listener.deinit(init.io);
    try server.serve(a, init.io, &listener);
}
