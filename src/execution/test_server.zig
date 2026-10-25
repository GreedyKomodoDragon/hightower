// A local execution anchor and one validated log-emitting block expose the
// JSON-RPC methods with real canonical transaction and receipt data. This is
// a fixture, not a node runtime: the pool accepts transactions but does not
// build further blocks.
const std = @import("std");
const execution = @import("execution");

/// Serves the in-memory execution fixture on loopback for HTTP and client tests.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    const port: u16 = if (args.len > 1) try std.fmt.parseInt(u16, args[1], 10) else 18545;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const sender: execution.Address = .{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    const recipient: execution.Address = .{0x22} ** 20;
    try world.setBalance(sender, 1_000_000_000_000_000_000);
    var code: [44]u8 = undefined;
    @memcpy(code[0..6], &[_]u8{ 0x60, 0x2a, 0x60, 0, 0x52, 0x7f });
    @memset(code[6..38], 0x11);
    @memcpy(code[38..], &[_]u8{ 0x60, 0x20, 0x60, 0, 0xa1, 0x00 });
    _ = try world.setCode(recipient, &code);
    _ = try world.setCode(.{0x55} ** 20, &.{ 0x60, 0, 0x60, 0, 0xfd });
    const zero: execution.Hash = .{0} ** 32;
    var header = std.mem.zeroes(execution.Header);
    header.parent_hash = zero;
    header.state_root = try world.stateRoot();
    header.gas_limit = 30_000_000;
    header.base_fee_per_gas = 1;
    var chain = try execution.chain.Chain.init(a, 1, .fulu, header, &world);
    defer chain.deinit();
    var tx = execution.Transaction{ .dynamic_fee = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 1, .max_fee_per_gas = 2, .gas_limit = 100_000, .to = recipient, .value = 0, .data = &.{}, .access_list = &.{}, .y_parity = 0, .r = 1, .s = 1 } };
    try signTransaction(a, &tx, sender);
    const raw = try execution.encode(a, tx);
    const context: execution.transition.Context = .{ .fork = .fulu, .chain_id = 1, .coinbase = .{0x33} ** 20, .number = 1, .timestamp = 1, .gas_limit = header.gas_limit, .base_fee = 1, .blob_base_fee = 1 };
    var simulated = try world.clone(a);
    defer simulated.deinit();
    var outcome = try execution.transition.applyTransaction(a, &simulated, context, raw, header.gas_limit, 0);
    defer outcome.deinit();
    var next = header;
    next.parent_hash = try execution.transition.headerHash(a, .fulu, header);
    next.number = 1;
    next.timestamp = 1;
    next.fee_recipient = context.coinbase;
    next.state_root = try simulated.stateRoot();
    next.transactions_root = try execution.trie.orderedRoot(a, &.{raw});
    next.receipts_root = try execution.receiptsRoot(a, &.{outcome.receipt});
    next.logs_bloom = execution.receiptsBloom(&.{outcome.receipt});
    next.withdrawals_root = try execution.trie.orderedRoot(a, &.{});
    next.gas_used = outcome.gas_used;
    try chain.append(&world, next, &.{raw}, &.{}, &.{});
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var server: execution.rpc.Server = .{ .chain = &chain, .pool = &pool, .world = &world, .settings = &settings };
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    var listener = try address.listen(init.io, .{ .reuse_address = true });
    defer listener.deinit(init.io);
    try server.serve(a, init.io, &listener);
}

/// Signs the fixture's EIP-1559 transaction with private key one.
fn signTransaction(a: std.mem.Allocator, tx: *execution.Transaction, sender: execution.Address) !void {
    const item = tx.dynamic_fee;
    const payload = try execution.encode(a, .{ item.chain_id, item.nonce, item.max_priority_fee_per_gas, item.max_fee_per_gas, item.gas_limit, item.to, item.value, item.data, item.access_list });
    defer a.free(payload);
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(&.{2});
    hasher.update(payload);
    var hash: execution.Hash = undefined;
    hasher.final(&hash);
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.Secp256k1, std.crypto.hash.sha3.Keccak256);
    var secret = [_]u8{0} ** 32;
    secret[31] = 1;
    const key_pair = try Scheme.KeyPair.fromSecretKey(.{ .bytes = secret });
    const signature = try key_pair.signPrehashed(hash, null);
    tx.dynamic_fee.r = std.mem.readInt(u256, &signature.r, .big);
    tx.dynamic_fee.s = std.mem.readInt(u256, &signature.s, .big);
    const order = std.crypto.ecc.Secp256k1.scalar.field_order;
    if (tx.dynamic_fee.s > order / 2) tx.dynamic_fee.s = order - tx.dynamic_fee.s;
    for (0..2) |parity| {
        tx.dynamic_fee.y_parity = @intCast(parity);
        const recovered = try execution.recoverSender(a, tx.*, 1);
        if (std.mem.eql(u8, &recovered, &sender)) return;
    }
    return error.SenderMismatch;
}
