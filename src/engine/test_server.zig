// A loopback Engine API fixture anchors an empty Osaka execution state. It
// exposes authenticated methods for client interoperability tests without
// starting a full Hightower node or persisting canonical history.
const std = @import("std");
const execution = @import("execution");
const engine = @import("engine_server");

/// Starts a local authenticated Engine API fixture and prints its genesis hash.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3) return error.ExpectedPortAndJwtFile;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const raw = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], a, .limited(128));
    const trimmed = std.mem.trim(u8, raw, " \r\n\t");
    if (trimmed.len != 64) return error.InvalidJwtSecret;
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, trimmed);
    var world = execution.state.State.init(a);
    defer world.deinit();
    var header = std.mem.zeroes(execution.Header);
    header.state_root = try world.stateRoot();
    header.gas_limit = 30_000_000;
    header.base_fee_per_gas = 1;
    var chain = try execution.chain.Chain.init(a, 1, .osaka, header, &world);
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
