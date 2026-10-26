// Execution RLP fixtures exercise ordered Fulu fields and all supported
// transaction envelopes. Encoded bytes are consensus-critical because changing
// even one field position changes the transaction or block hash.
const std = @import("std");
const execution = @import("execution");
test {
    _ = execution.pool;
    _ = execution.chain;
    _ = execution.rpc;
}

test "pinned c-kzg zero-blob vector accepts its proof and rejects another" {
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    const ckzg = @import("ckzg");
    const blob: ckzg.Blob = .{ .bytes = .{0} ** ckzg.BYTES_PER_BLOB };
    const commitment: ckzg.Bytes48 = .{ .bytes = .{0xc0} ++ (.{0} ** 47) };
    const correct: ckzg.Bytes48 = commitment;
    var incorrect: ckzg.Bytes48 = undefined;
    _ = try std.fmt.hexToBytes(&incorrect.bytes, "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    try std.testing.expect(try settings.verifyBlobKzgProof(&blob, &commitment, &correct));
    try std.testing.expect(!(try settings.verifyBlobKzgProof(&blob, &commitment, &incorrect)));
}

test "blob and Fulu cell wrappers verify and retain canonical transaction bytes" {
    const a = std.testing.allocator;
    const ckzg = @import("ckzg");
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    const blob: ckzg.Blob = .{ .bytes = .{0} ** ckzg.BYTES_PER_BLOB };
    const commitment: [48]u8 = .{0xc0} ++ (.{0} ** 47);
    const proof: [48]u8 = commitment;
    var hash: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &hash, .{});
    hash[0] = 1;
    const tx: execution.Blob = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 2,
        .gas_limit = 100_000,
        .to = .{0x22} ** 20,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &.{hash},
        .y_parity = 0,
        .r = 1,
        .s = 1,
    };
    const canonical = try execution.encode(a, execution.Transaction{ .blob = tx });
    defer a.free(canonical);
    const blobs = [1][ckzg.BYTES_PER_BLOB]u8{blob.bytes};
    const commitments = [1][48]u8{commitment};
    const proofs = [1][48]u8{proof};
    const wrapper = try execution.encode(a, .{ tx, blobs, commitments, proofs });
    defer a.free(wrapper);
    const raw = try a.alloc(u8, wrapper.len + 1);
    defer a.free(raw);
    raw[0] = 3;
    @memcpy(raw[1..], wrapper);
    const recovered = try execution.kzg.canonicalTransaction(a, &settings, raw);
    defer a.free(recovered);
    try std.testing.expectEqualSlices(u8, canonical, recovered);
    raw[raw.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidBlobProof, execution.kzg.canonicalTransaction(a, &settings, raw));
    raw[raw.len - 1] ^= 1;
    var cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
    var cell_proofs: [ckzg.CELLS_PER_EXT_BLOB]ckzg.KzgProof = undefined;
    try settings.computeCellsAndKzgProofs(&cells, &cell_proofs, &blob);
    var cell_bytes: [ckzg.CELLS_PER_EXT_BLOB][48]u8 = undefined;
    for (cell_proofs, 0..) |item, i| cell_bytes[i] = item.bytes;
    const cell_wrapper = try execution.encode(a, .{ tx, @as(u8, 1), blobs, commitments, cell_bytes });
    defer a.free(cell_wrapper);
    const cell_raw = try a.alloc(u8, cell_wrapper.len + 1);
    defer a.free(cell_raw);
    cell_raw[0] = 3;
    @memcpy(cell_raw[1..], cell_wrapper);
    const cell_recovered = try execution.kzg.canonicalTransaction(a, &settings, cell_raw);
    defer a.free(cell_recovered);
    try std.testing.expectEqualSlices(u8, canonical, cell_recovered);
}

test "execution JSON-RPC dispatches chain and block methods with bounded input" {
    const a = std.testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const zero_hash = [_]u8{0} ** 32;
    const header: execution.Header = .{
        .parent_hash = zero_hash,
        .ommers_hash = zero_hash,
        .fee_recipient = .{0} ** 20,
        .state_root = try world.stateRoot(),
        .transactions_root = zero_hash,
        .receipts_root = zero_hash,
        .logs_bloom = .{0} ** 256,
        .difficulty = 0,
        .number = 0,
        .gas_limit = 30_000_000,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = &.{},
        .prev_randao = zero_hash,
        .nonce = .{0} ** 8,
        .base_fee_per_gas = 1,
        .withdrawals_root = zero_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = zero_hash,
        .requests_hash = zero_hash,
    };
    var chain = try execution.chain.Chain.init(a, 1, .fulu, header, &world);
    defer chain.deinit();
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    var server: execution.rpc.Server = .{ .chain = &chain, .pool = &pool, .world = &world };
    const response = try server.dispatch(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}");
    defer a.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"result\":\"0x1\"") != null);
    const invalid = try server.dispatch(a, "[{},{}]");
    defer a.free(invalid);
    try std.testing.expect(std.mem.indexOf(u8, invalid, "-32600") != null);
    const requests = [_][]const u8{
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_blockNumber\",\"params\":[]}",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_getBlockByNumber\",\"params\":[\"latest\",false]}",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"eth_getBalance\",\"params\":[\"0x0000000000000000000000000000000000000000\",\"latest\"]}",
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x0000000000000000000000000000000000000000\"},\"latest\"]}",
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"eth_estimateGas\",\"params\":[{\"to\":\"0x0000000000000000000000000000000000000000\"},\"latest\"]}",
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"0x0000000000000000000000000000000000000000000000000000000000000000\"]}",
        "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"eth_getLogs\",\"params\":[{}]}",
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x\"]}",
    };
    for (requests) |request| {
        const reply = try server.dispatch(a, request);
        defer a.free(reply);
        var parsed = try std.json.parseFromSlice(std.json.Value, a, reply, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.object.contains("result") or parsed.value.object.contains("error"));
    }
    const serve_fn: *const fn (*execution.rpc.Server, std.mem.Allocator, std.Io, std.Io.net.Stream) anyerror!void = execution.rpc.Server.serveConnection;
    _ = serve_fn;
}

test "pool budgets blobs, preserves nonce gaps, selects prefixes, and enforces replacement" {
    const a = std.testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const sender: execution.Address = .{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    try world.setBalance(sender, 1_000_000_000_000);
    const context: execution.transition.Context = .{ .fork = .fulu, .chain_id = 1, .coinbase = .{0x33} ** 20, .number = 1, .timestamp = 1, .gas_limit = 1_000_000, .base_fee = 1, .blob_base_fee = 1 };
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var pool = execution.pool.Pool.init(a, .{ .max_entries = 8, .max_bytes = 2 * 1024 * 1024 });
    defer pool.deinit();
    const commitment: [48]u8 = .{0xc0} ++ (.{0} ** 47);
    var versioned_hash: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &versioned_hash, .{});
    versioned_hash[0] = 1;
    const auth = execution.Authorization{ .chain_id = 1, .address = .{0x44} ** 20, .nonce = 0, .y_parity = 0, .r = 1, .s = 1 };
    for (0..6) |n| {
        var tx: execution.Transaction = switch (n) {
            0 => .{ .legacy = .{ .nonce = 0, .gas_price = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .v = 27, .r = 1, .s = 1 } },
            1 => .{ .access_list = .{ .chain_id = 1, .nonce = 1, .gas_price = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .y_parity = 0, .r = 1, .s = 1 } },
            2 => .{ .dynamic_fee = .{ .chain_id = 1, .nonce = 2, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .y_parity = 0, .r = 1, .s = 1 } },
            3 => .{ .blob = .{ .chain_id = 1, .nonce = 3, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .max_fee_per_blob_gas = 10, .blob_versioned_hashes = &.{versioned_hash}, .y_parity = 0, .r = 1, .s = 1 } },
            4 => .{ .blob = .{ .chain_id = 1, .nonce = 4, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .max_fee_per_blob_gas = 10, .blob_versioned_hashes = &.{versioned_hash}, .y_parity = 0, .r = 1, .s = 1 } },
            5 => .{ .set_code = .{ .chain_id = 1, .nonce = 5, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .destination = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .authorization_list = &.{auth}, .y_parity = 0, .r = 1, .s = 1 } },
            else => unreachable,
        };
        try expectSyntheticSender(a, &tx);
        const raw = if (tx == .blob) blk: {
            const blob = [_][131_072]u8{.{0} ** 131_072};
            const commitments = [_][48]u8{commitment};
            const proofs = [_][48]u8{commitment};
            const payload = try execution.encode(a, .{ tx.blob, blob, commitments, proofs });
            defer a.free(payload);
            const network = try a.alloc(u8, payload.len + 1);
            network[0] = 3;
            @memcpy(network[1..], payload);
            break :blk network;
        } else try execution.encode(a, tx);
        defer a.free(raw);
        _ = try pool.admit(&world, context, &settings, raw);
    }
    try testing.expectEqual(@as(usize, 6), pool.entries.items.len);
    const original = try world.stateRoot();
    const bounded = try pool.select(a, &world, context, 150_000, 1);
    defer a.free(bounded);
    try testing.expectEqual(@as(usize, 3), bounded.len);
    try testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
    const selected = try pool.select(a, &world, context, 1_000_000, 1);
    defer a.free(selected);
    try testing.expectEqual(@as(usize, 4), selected.len);
    const both_blobs = try pool.select(a, &world, context, 1_000_000, 2);
    defer a.free(both_blobs);
    try testing.expectEqual(@as(usize, 6), both_blobs.len);
    try testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
    const no_blob = try pool.select(a, &world, context, 1_000_000, 0);
    defer a.free(no_blob);
    try testing.expectEqual(@as(usize, 3), no_blob.len);
    try testing.expectEqual(@as(usize, 6), pool.entries.items.len);
    try testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
    var gap = execution.Transaction{ .dynamic_fee = .{ .chain_id = 1, .nonce = 7, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .y_parity = 0, .r = 1, .s = 1 } };
    try expectSyntheticSender(a, &gap);
    const gap_raw = try execution.encode(a, gap);
    defer a.free(gap_raw);
    _ = try pool.admit(&world, context, &settings, gap_raw);
    const selected_gap = try pool.select(a, &world, context, 1_000_000, 2);
    defer a.free(selected_gap);
    try testing.expectEqual(@as(usize, 6), selected_gap.len);
    gap.dynamic_fee.max_fee_per_gas = 109;
    gap.dynamic_fee.max_priority_fee_per_gas = 11;
    try expectSyntheticSender(a, &gap);
    const underpriced = try execution.encode(a, gap);
    defer a.free(underpriced);
    try testing.expectError(error.ReplacementUnderpriced, pool.admit(&world, context, &settings, underpriced));
    gap.dynamic_fee.max_fee_per_gas = 110;
    try expectSyntheticSender(a, &gap);
    const replacement = try execution.encode(a, gap);
    defer a.free(replacement);
    _ = try pool.admit(&world, context, &settings, replacement);
}

/// Builds a signed dynamic-fee transaction at one nonce for pool bound tests.
fn pendingDynamic(a: std.mem.Allocator, nonce: u64) ![]u8 {
    var tx = execution.Transaction{ .dynamic_fee = .{ .chain_id = 1, .nonce = nonce, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .y_parity = 0, .r = 1, .s = 1 } };
    try expectSyntheticSender(a, &tx);
    return execution.encode(a, tx);
}

test "pool evicts by count and bytes and prunes mined nonces" {
    const a = testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const sender: execution.Address = .{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    try world.setBalance(sender, 1_000_000_000);
    const context: execution.transition.Context = .{ .fork = .fulu, .chain_id = 1, .coinbase = .{0x33} ** 20, .number = 1, .timestamp = 1, .gas_limit = 1_000_000, .base_fee = 1, .blob_base_fee = 1 };
    const raws = [_][]u8{ try pendingDynamic(a, 0), try pendingDynamic(a, 1), try pendingDynamic(a, 2) };
    defer for (raws) |raw| a.free(raw);
    for ([_]execution.pool.Limits{ .{ .max_entries = 2, .max_bytes = 1024 }, .{ .max_entries = 10, .max_bytes = raws[0].len + raws[1].len } }) |limits| {
        var pool = execution.pool.Pool.init(a, limits);
        defer pool.deinit();
        for (raws[0..2]) |raw| _ = try pool.admit(&world, context, null, raw);
        try testing.expectError(error.PoolFull, pool.admit(&world, context, null, raws[2]));
        try testing.expectEqual(@as(usize, 2), pool.entries.items.len);
        try testing.expectEqual(@as(u64, 0), pool.entries.items[0].admission.nonce);
        try testing.expectEqual(@as(u64, 1), pool.entries.items[1].admission.nonce);
        try world.setNonce(sender, 1);
        pool.prune(&world);
        try testing.expectEqual(@as(usize, 1), pool.entries.items.len);
        try testing.expectError(error.InvalidNonce, pool.admit(&world, context, null, raws[0]));
        try world.setNonce(sender, 0);
    }
}

test "pool keeps the accepted transaction when a larger replacement loses eviction" {
    const a = testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const sender: execution.Address = .{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    try world.setBalance(sender, 1_000_000_000);
    const context: execution.transition.Context = .{ .fork = .fulu, .chain_id = 1, .coinbase = .{0x33} ** 20, .number = 1, .timestamp = 1, .gas_limit = 1_000_000, .base_fee = 1, .blob_base_fee = 1 };
    var low = execution.Transaction{ .dynamic_fee = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .y_parity = 0, .r = 1, .s = 1 } };
    try expectSyntheticSender(a, &low);
    const old_raw = try execution.encode(a, low);
    defer a.free(old_raw);
    var high = low;
    high.dynamic_fee.nonce = 1;
    high.dynamic_fee.max_priority_fee_per_gas = 100;
    high.dynamic_fee.max_fee_per_gas = 1000;
    try expectSyntheticSender(a, &high);
    const high_raw = try execution.encode(a, high);
    defer a.free(high_raw);
    var pool = execution.pool.Pool.init(a, .{ .max_entries = 3, .max_bytes = old_raw.len + high_raw.len });
    defer pool.deinit();
    const old_hash = try pool.admit(&world, context, null, old_raw);
    const high_hash = try pool.admit(&world, context, null, high_raw);
    var replacement = low;
    replacement.dynamic_fee.max_priority_fee_per_gas = 11;
    replacement.dynamic_fee.max_fee_per_gas = 110;
    replacement.dynamic_fee.data = &([_]u8{1} ** 64);
    try expectSyntheticSender(a, &replacement);
    const replacement_raw = try execution.encode(a, replacement);
    defer a.free(replacement_raw);
    try testing.expectError(error.PoolFull, pool.admit(&world, context, null, replacement_raw));
    try testing.expectEqual(@as(usize, 2), pool.entries.items.len);
    try testing.expectEqual(old_raw.len + high_raw.len, pool.byte_count);
    try testing.expectEqualSlices(u8, old_raw, pool.get(old_hash).?.raw);
    try testing.expectEqualSlices(u8, high_raw, pool.get(high_hash).?.raw);
}
const rlp = @import("rlp");
const testing = std.testing;

test {
    _ = @import("trie_test.zig");
}

/// Recovers and checks the oracle sender from one pinned transaction fixture.
fn expectFixtureSender(json_bytes: []const u8, fork: []const u8, expected_chain_id: u256) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json_bytes, .{});
    defer parsed.deinit();
    const test_case = parsed.value.object.values()[0];
    const hex = test_case.object.get("txbytes").?.string;
    const raw = try testing.allocator.alloc(u8, (hex.len - 2) / 2);
    defer testing.allocator.free(raw);
    _ = try std.fmt.hexToBytes(raw, hex[2..]);

    var transaction = try execution.parse(execution.Transaction, testing.allocator, raw);
    defer transaction.deinit();
    const sender = try execution.recoverSender(testing.allocator, transaction.value, expected_chain_id);
    const expected_hex = test_case.object.get("result").?.object.get(fork).?.object.get("sender").?.string;
    var expected: execution.Address = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex[2..]);
    try testing.expectEqualSlices(u8, &expected, &sender);
}

/// Independently assembles typed signing payloads for deterministic recovery tests.
fn expectedSigningHash(allocator: std.mem.Allocator, transaction: execution.Transaction) ![32]u8 {
    const tag: ?u8 = switch (transaction) {
        .legacy => null,
        .access_list => 1,
        .dynamic_fee => 2,
        .blob => 3,
        .set_code => 4,
    };
    const payload = switch (transaction) {
        .legacy => |tx| try execution.encode(allocator, .{ tx.nonce, tx.gas_price, tx.gas_limit, tx.to, tx.value, tx.data }),
        .access_list => |tx| try execution.encode(allocator, .{ tx.chain_id, tx.nonce, tx.gas_price, tx.gas_limit, tx.to, tx.value, tx.data, tx.access_list }),
        .dynamic_fee => |tx| try execution.encode(allocator, .{ tx.chain_id, tx.nonce, tx.max_priority_fee_per_gas, tx.max_fee_per_gas, tx.gas_limit, tx.to, tx.value, tx.data, tx.access_list }),
        .blob => |tx| try execution.encode(allocator, .{ tx.chain_id, tx.nonce, tx.max_priority_fee_per_gas, tx.max_fee_per_gas, tx.gas_limit, tx.to, tx.value, tx.data, tx.access_list, tx.max_fee_per_blob_gas, tx.blob_versioned_hashes }),
        .set_code => |tx| try execution.encode(allocator, .{ tx.chain_id, tx.nonce, tx.max_priority_fee_per_gas, tx.max_fee_per_gas, tx.gas_limit, tx.destination, tx.value, tx.data, tx.access_list, tx.authorization_list }),
    };
    defer allocator.free(payload);
    var hash: [32]u8 = undefined;
    if (tag) |typed_tag| {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&.{typed_tag});
        hasher.update(payload);
        hasher.final(&hash);
    } else {
        std.crypto.hash.sha3.Keccak256.hash(payload, &hash, .{});
    }
    return hash;
}

/// Signs a typed test transaction with private key 1 and checks the recovered known address.
fn expectSyntheticSender(allocator: std.mem.Allocator, transaction: *execution.Transaction) !void {
    const hash = try expectedSigningHash(allocator, transaction.*);
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.Secp256k1, std.crypto.hash.sha3.Keccak256);
    var secret_key = [_]u8{0} ** 32;
    secret_key[31] = 1;
    const key_pair = try Scheme.KeyPair.fromSecretKey(.{ .bytes = secret_key });
    const signature = try key_pair.signPrehashed(hash, null);
    const r = std.mem.readInt(u256, &signature.r, .big);
    var s = std.mem.readInt(u256, &signature.s, .big);
    const order = std.crypto.ecc.Secp256k1.scalar.field_order;
    if (s > order / 2) s = order - s;
    switch (transaction.*) {
        .legacy => |*tx| {
            tx.r = r;
            tx.s = s;
        },
        .access_list => |*tx| {
            tx.r = r;
            tx.s = s;
        },
        .dynamic_fee => |*tx| {
            tx.r = r;
            tx.s = s;
        },
        .blob => |*tx| {
            tx.r = r;
            tx.s = s;
        },
        .set_code => |*tx| {
            tx.r = r;
            tx.s = s;
        },
    }
    const expected = [_]u8{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    var recovered = false;
    for (0..2) |parity| {
        switch (transaction.*) {
            .legacy => |*tx| tx.v = 27 + parity,
            .access_list => |*tx| tx.y_parity = @intCast(parity),
            .dynamic_fee => |*tx| tx.y_parity = @intCast(parity),
            .blob => |*tx| tx.y_parity = @intCast(parity),
            .set_code => |*tx| tx.y_parity = @intCast(parity),
        }
        const address = try execution.recoverSender(allocator, transaction.*, 1);
        if (std.mem.eql(u8, &address, &expected)) {
            recovered = true;
            break;
        }
    }
    try testing.expect(recovered);
}

/// Signs one EIP-7702 authorization using the synthetic test key.
fn signedAuthorization(a: std.mem.Allocator, target: execution.Address, nonce: u64) !execution.Authorization {
    var auth: execution.Authorization = .{ .chain_id = 1, .address = target, .nonce = nonce, .y_parity = 0, .r = 0, .s = 0 };
    const encoded = try execution.encode(a, .{ auth.chain_id, auth.address, auth.nonce });
    defer a.free(encoded);
    const message = try a.alloc(u8, encoded.len + 1);
    defer a.free(message);
    message[0] = 5;
    @memcpy(message[1..], encoded);
    var hash: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(message, &hash, .{});
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.Secp256k1, std.crypto.hash.sha3.Keccak256);
    var secret = [_]u8{0} ** 32;
    secret[31] = 1;
    const pair = try Scheme.KeyPair.fromSecretKey(.{ .bytes = secret });
    const signature = try pair.signPrehashed(hash, null);
    auth.r = std.mem.readInt(u256, &signature.r, .big);
    auth.s = std.mem.readInt(u256, &signature.s, .big);
    const order = std.crypto.ecc.Secp256k1.scalar.field_order;
    if (auth.s > order / 2) auth.s = order - auth.s;
    const sender: execution.Address = .{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    for (0..2) |parity| {
        const recovered = try execution.crypto.recoverAddress(hash, auth.r, auth.s, @intCast(parity));
        if (std.mem.eql(u8, &recovered, &sender)) {
            auth.y_parity = @intCast(parity);
            return auth;
        }
    }
    return error.SenderMismatch;
}

test "blob fees and BLOBHASH execute, while bad fees and signatures roll back" {
    const a = testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const sender: execution.Address = .{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    const recipient: execution.Address = .{0x22} ** 20;
    try world.setBalance(sender, 1_000_000_000);
    _ = try world.setCode(recipient, &.{ 0x60, 0, 0x49, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 });
    const commitment: [48]u8 = .{0xc0} ++ (.{0} ** 47);
    var versioned_hash: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &versioned_hash, .{});
    versioned_hash[0] = 1;
    var tx = execution.Transaction{ .blob = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 10, .max_fee_per_gas = 100, .gas_limit = 100_000, .to = recipient, .value = 0, .data = &.{}, .access_list = &.{}, .max_fee_per_blob_gas = 1, .blob_versioned_hashes = &.{versioned_hash}, .y_parity = 0, .r = 1, .s = 1 } };
    try expectSyntheticSender(a, &tx);
    const raw = try execution.encode(a, tx);
    defer a.free(raw);
    const context: execution.transition.Context = .{ .fork = .fulu, .chain_id = 1, .coinbase = .{0x33} ** 20, .number = 1, .timestamp = 1, .gas_limit = 1_000_000, .base_fee = 1, .blob_base_fee = 1 };
    const root = try world.stateRoot();
    var block_world = try world.clone(a);
    defer block_world.deinit();
    var parent = std.mem.zeroes(execution.Header);
    parent.gas_limit = context.gas_limit;
    parent.base_fee_per_gas = 1;
    var header = std.mem.zeroes(execution.Header);
    header.parent_hash = try execution.transition.headerHash(a, .fulu, parent);
    header.number = 1;
    header.timestamp = 1;
    header.gas_limit = context.gas_limit;
    header.base_fee_per_gas = 1;
    header.blob_gas_used = 131_072;
    try testing.expectError(error.InvalidVersionedHashes, execution.transition.applyBlock(a, &block_world, .{ .fork = .fulu, .parent_fork = .fulu, .chain_id = 1 }, parent, header, &.{raw}, &.{}));
    try testing.expectEqualSlices(u8, &root, &(try block_world.stateRoot()));
    var high_fee = context;
    high_fee.blob_base_fee = 2;
    try testing.expectError(error.InvalidBlobFee, execution.transition.applyTransaction(a, &world, high_fee, raw, context.gas_limit, 0));
    try testing.expectEqualSlices(u8, &root, &(try world.stateRoot()));
    var bad = tx;
    bad.blob.r = 0;
    const bad_raw = try execution.encode(a, bad);
    defer a.free(bad_raw);
    try testing.expectError(error.InvalidSignature, execution.transition.applyTransaction(a, &world, context, bad_raw, context.gas_limit, 0));
    try testing.expectEqualSlices(u8, &root, &(try world.stateRoot()));
    var outcome = try execution.transition.applyTransaction(a, &world, context, raw, context.gas_limit, 0);
    defer outcome.deinit();
    try testing.expect(outcome.receipt == .blob);
    try testing.expectEqualSlices(u8, &versioned_hash, outcome.output);
    try testing.expectEqual(@as(u256, 1_000_000_000 - @as(u256, outcome.gas_used) * 11 - 131_072), world.getBalance(sender));
}

test "set-code authorization persists through delegated execution" {
    const a = testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const sender: execution.Address = .{ 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };
    const target: execution.Address = .{0x44} ** 20;
    try world.setBalance(sender, 1_000_000_000);
    _ = try world.setCode(target, &.{ 0x60, 0x2a, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 });
    const auth = try signedAuthorization(a, target, 1);
    var tx = execution.Transaction{ .set_code = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 1, .max_fee_per_gas = 2, .gas_limit = 100_000, .destination = sender, .value = 0, .data = &.{}, .access_list = &.{}, .authorization_list = &.{auth}, .y_parity = 0, .r = 1, .s = 1 } };
    try expectSyntheticSender(a, &tx);
    const raw = try execution.encode(a, tx);
    defer a.free(raw);
    const context: execution.transition.Context = .{ .fork = .fulu, .chain_id = 1, .coinbase = .{0x33} ** 20, .number = 1, .timestamp = 1, .gas_limit = 1_000_000, .base_fee = 1, .blob_base_fee = 1 };
    const original = try world.stateRoot();
    var too_little_gas = tx;
    too_little_gas.set_code.gas_limit = 45_999;
    try expectSyntheticSender(a, &too_little_gas);
    const low_gas_raw = try execution.encode(a, too_little_gas);
    defer a.free(low_gas_raw);
    try testing.expectError(error.IntrinsicGasTooLow, execution.transition.applyTransaction(a, &world, context, low_gas_raw, context.gas_limit, 0));
    try testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
    var invalid_auth = tx;
    var invalid_tuple = auth;
    invalid_tuple.r = 0;
    invalid_auth.set_code.authorization_list = &.{invalid_tuple};
    try expectSyntheticSender(a, &invalid_auth);
    const invalid_raw = try execution.encode(a, invalid_auth);
    defer a.free(invalid_raw);
    var ignored_world = try world.clone(a);
    defer ignored_world.deinit();
    var ignored = try execution.transition.applyTransaction(a, &ignored_world, context, invalid_raw, context.gas_limit, 0);
    defer ignored.deinit();
    try testing.expectEqual(@as(usize, 0), ignored_world.getCode(sender).len);
    try testing.expectEqual(@as(u64, 1), ignored_world.getNonce(sender));
    var outcome = try execution.transition.applyTransaction(a, &world, context, raw, context.gas_limit, 0);
    defer outcome.deinit();
    try testing.expect(outcome.receipt == .set_code);
    try testing.expectEqual(@as(u64, 2), world.getNonce(sender));
    try testing.expectEqual(@as(usize, 23), world.getCode(sender).len);
    try testing.expectEqual(@as(u8, 0x2a), outcome.output[31]);
    _ = try world.setCode(target, &.{ 0x60, 0, 0x60, 0, 0xfd });
    const second_auth = try signedAuthorization(a, target, 3);
    tx.set_code.nonce = 2;
    tx.set_code.authorization_list = &.{second_auth};
    try expectSyntheticSender(a, &tx);
    const reverting = try execution.encode(a, tx);
    defer a.free(reverting);
    var reverted = try execution.transition.applyTransaction(a, &world, context, reverting, context.gas_limit, 0);
    defer reverted.deinit();
    try testing.expectEqual(@as(u8, 0), reverted.receipt.set_code.status);
    try testing.expectEqual(@as(u64, 4), world.getNonce(sender));
    try testing.expectEqual(@as(usize, 23), world.getCode(sender).len);
}

test "sender recovery matches pinned legacy and typed transaction fixtures" {
    try expectFixtureSender(@embedFile("fixtures/tx_simple_type_0_shanghai.json"), "Shanghai", 1);
    try expectFixtureSender(@embedFile("fixtures/accessListStorage32Bytes.json"), "Cancun", 1);
}

const SenderVector = struct {
    name: []const u8,
    source: []const u8,
    transaction_type: u8,
    chain_id: u256,
    y_parity: u8,
    txbytes: []const u8,
    sender: []const u8,
};

test "sender recovery matches pinned type 2 3 and 4 vectors and exact parity" {
    var vectors = try std.json.parseFromSlice([]SenderVector, testing.allocator, @embedFile("fixtures/sender_recovery_vectors.json"), .{});
    defer vectors.deinit();
    try testing.expectEqual(@as(usize, 3), vectors.value.len);
    for (vectors.value, 2..) |vector, expected_type| {
        try testing.expectEqual(@as(u8, @intCast(expected_type)), vector.transaction_type);
        try testing.expect(std.mem.startsWith(u8, vector.txbytes, "0x"));
        const raw = try testing.allocator.alloc(u8, (vector.txbytes.len - 2) / 2);
        defer testing.allocator.free(raw);
        _ = try std.fmt.hexToBytes(raw, vector.txbytes[2..]);
        try testing.expectEqual(vector.transaction_type, raw[0]);

        var transaction = try execution.parse(execution.Transaction, testing.allocator, raw);
        defer transaction.deinit();
        const parity = switch (transaction.value) {
            .dynamic_fee => |tx| tx.y_parity,
            .blob => |tx| tx.y_parity,
            .set_code => |tx| tx.y_parity,
            else => return error.UnexpectedTransactionType,
        };
        try testing.expectEqual(vector.y_parity, parity);

        var expected: execution.Address = undefined;
        try testing.expect(std.mem.startsWith(u8, vector.sender, "0x"));
        _ = try std.fmt.hexToBytes(&expected, vector.sender[2..]);
        const sender = try execution.recoverSender(testing.allocator, transaction.value, vector.chain_id);
        try testing.expectEqualSlices(u8, &expected, &sender);
        try testing.expectError(error.ChainIdMismatch, execution.recoverSender(testing.allocator, transaction.value, vector.chain_id + 1));

        switch (transaction.value) {
            .dynamic_fee => |*tx| tx.y_parity ^= 1,
            .blob => |*tx| tx.y_parity ^= 1,
            .set_code => |*tx| tx.y_parity ^= 1,
            else => unreachable,
        }
        const other_sender = try execution.recoverSender(testing.allocator, transaction.value, vector.chain_id);
        try testing.expect(!std.mem.eql(u8, &expected, &other_sender));
    }
}

test "sender recovery hashes dynamic fee blob and set-code typed payloads" {
    var dynamic = execution.Transaction{ .dynamic_fee = .{
        .chain_id = 1,
        .nonce = 2,
        .max_priority_fee_per_gas = 3,
        .max_fee_per_gas = 4,
        .gas_limit = 5,
        .to = null,
        .value = 6,
        .data = "dynamic",
        .access_list = &.{},
        .y_parity = 0,
        .r = 1,
        .s = 1,
    } };
    var blob = execution.Transaction{ .blob = .{
        .chain_id = 1,
        .nonce = 2,
        .max_priority_fee_per_gas = 3,
        .max_fee_per_gas = 4,
        .gas_limit = 5,
        .to = [_]u8{0x11} ** 20,
        .value = 6,
        .data = "blob",
        .access_list = &.{},
        .max_fee_per_blob_gas = 7,
        .blob_versioned_hashes = &.{},
        .y_parity = 0,
        .r = 1,
        .s = 1,
    } };
    var set_code = execution.Transaction{ .set_code = .{
        .chain_id = 1,
        .nonce = 2,
        .max_priority_fee_per_gas = 3,
        .max_fee_per_gas = 4,
        .gas_limit = 5,
        .destination = [_]u8{0x22} ** 20,
        .value = 6,
        .data = "set-code",
        .access_list = &.{},
        .authorization_list = &.{},
        .y_parity = 0,
        .r = 1,
        .s = 1,
    } };
    try expectSyntheticSender(testing.allocator, &dynamic);
    try expectSyntheticSender(testing.allocator, &blob);
    try expectSyntheticSender(testing.allocator, &set_code);
}

test "sender recovery accepts replay-unprotected legacy transactions" {
    var legacy = execution.Transaction{ .legacy = .{
        .nonce = 1,
        .gas_price = 2,
        .gas_limit = 21_000,
        .to = [_]u8{0x11} ** 20,
        .value = 3,
        .data = "legacy",
        .v = 27,
        .r = 1,
        .s = 1,
    } };
    try expectSyntheticSender(testing.allocator, &legacy);
}

test "sender recovery rejects invalid v parity chain ID and high s" {
    var legacy_json = try std.json.parseFromSlice(std.json.Value, testing.allocator, @embedFile("fixtures/tx_simple_type_0_shanghai.json"), .{});
    defer legacy_json.deinit();
    const legacy_case = legacy_json.value.object.values()[0];
    const legacy_hex = legacy_case.object.get("txbytes").?.string;
    const legacy_raw = try testing.allocator.alloc(u8, (legacy_hex.len - 2) / 2);
    defer testing.allocator.free(legacy_raw);
    _ = try std.fmt.hexToBytes(legacy_raw, legacy_hex[2..]);
    var legacy = try execution.parse(execution.Transaction, testing.allocator, legacy_raw);
    defer legacy.deinit();
    legacy.value.legacy.v = 34;
    try testing.expectError(error.InvalidV, execution.recoverSender(testing.allocator, legacy.value, 1));
    legacy.value.legacy.v = 38;
    try testing.expectError(error.ChainIdMismatch, execution.recoverSender(testing.allocator, legacy.value, 2));
    const curve_order = std.crypto.ecc.Secp256k1.scalar.field_order;
    legacy.value.legacy.r = 0;
    try testing.expectError(error.InvalidSignature, execution.recoverSender(testing.allocator, legacy.value, 1));
    legacy.value.legacy.r = curve_order;
    try testing.expectError(error.InvalidSignature, execution.recoverSender(testing.allocator, legacy.value, 1));
    legacy.value.legacy.r = 1;
    legacy.value.legacy.s = 0;
    try testing.expectError(error.InvalidSignature, execution.recoverSender(testing.allocator, legacy.value, 1));
    legacy.value.legacy.s = curve_order - 1;
    try testing.expectError(error.HighS, execution.recoverSender(testing.allocator, legacy.value, 1));

    var typed_json = try std.json.parseFromSlice(std.json.Value, testing.allocator, @embedFile("fixtures/accessListStorage32Bytes.json"), .{});
    defer typed_json.deinit();
    const typed_case = typed_json.value.object.values()[0];
    const typed_hex = typed_case.object.get("txbytes").?.string;
    const typed_raw = try testing.allocator.alloc(u8, (typed_hex.len - 2) / 2);
    defer testing.allocator.free(typed_raw);
    _ = try std.fmt.hexToBytes(typed_raw, typed_hex[2..]);
    var typed = try execution.parse(execution.Transaction, testing.allocator, typed_raw);
    defer typed.deinit();
    typed.value.access_list.y_parity = 2;
    try testing.expectError(error.InvalidYParity, execution.recoverSender(testing.allocator, typed.value, 1));
    typed.value.access_list.y_parity = 1;
    try testing.expectError(error.ChainIdMismatch, execution.recoverSender(testing.allocator, typed.value, 2));
}

// Account and storage updates must change the secure state commitment.
test "execution state creates updates and deletes accounts and storage" {
    var state = execution.state.State.init(testing.allocator);
    defer state.deinit();
    const empty_root = try state.stateRoot();
    try testing.expectEqualSlices(u8, &execution.state.EMPTY_STORAGE_ROOT, &empty_root);

    const address = [_]u8{0x11} ** 20;
    try testing.expect((try state.getAccount(address)) == null);
    try testing.expectEqual(@as(u64, 0), state.getNonce(address));
    try testing.expectEqual(@as(u256, 0), state.getBalance(address));
    try testing.expectEqual(@as(u256, 0), state.getStorage(address, 3));
    try testing.expectEqualSlices(u8, "", state.getCode(address));

    try state.createAccount(address);
    const created = try state.stateRoot();
    try testing.expect(!std.mem.eql(u8, &created, &empty_root));
    const account = (try state.getAccount(address)).?;
    try testing.expectEqual(@as(u64, 0), account.nonce);
    try testing.expectEqual(@as(u256, 0), account.balance);
    try testing.expectEqualSlices(u8, &execution.state.EMPTY_STORAGE_ROOT, &account.storage_root);
    try testing.expectEqualSlices(u8, &execution.state.EMPTY_CODE_HASH, &account.code_hash);

    try state.setNonce(address, std.math.maxInt(u64));
    try state.setBalance(address, std.math.maxInt(u256));
    const updated = try state.stateRoot();
    try testing.expect(!std.mem.eql(u8, &updated, &created));
    try testing.expectEqual(std.math.maxInt(u64), state.getNonce(address));
    try testing.expectEqual(std.math.maxInt(u256), state.getBalance(address));

    const max_slot = std.math.maxInt(u256);
    const max_value = std.math.maxInt(u256);
    try state.setStorage(address, 0, 0x1234);
    try state.setStorage(address, max_slot, max_value);
    const with_storage = try state.stateRoot();
    try testing.expect(!std.mem.eql(u8, &with_storage, &updated));
    try testing.expectEqual(@as(u256, 0x1234), state.getStorage(address, 0));
    try testing.expectEqual(max_value, state.getStorage(address, max_slot));
    try state.setStorage(address, 0, 0);
    try state.setStorage(address, max_slot, 0);
    try testing.expectEqual(@as(u256, 0), state.getStorage(address, 0));
    try testing.expectEqual(@as(u256, 0), state.getStorage(address, max_slot));
    try testing.expectEqualSlices(u8, &updated, &(try state.stateRoot()));

    const code_hash = try state.setCode(address, "contract bytecode");
    try testing.expectEqualSlices(u8, "contract bytecode", state.getCode(address));
    const with_code = try state.getAccount(address);
    try testing.expectEqualSlices(u8, &code_hash, &with_code.?.code_hash);

    try state.deleteAccount(address);
    try testing.expect((try state.getAccount(address)) == null);
    try testing.expectEqualSlices(u8, &empty_root, &(try state.stateRoot()));
}

// Nested journal snapshots restore roots, and committing an inner snapshot keeps parent history.
test "execution state snapshots revert and commit in LIFO order" {
    var state = execution.state.State.init(testing.allocator);
    defer state.deinit();
    const address = [_]u8{0x22} ** 20;
    const empty_root = try state.stateRoot();

    const outer = try state.snapshot();
    try state.setBalance(address, 10);
    const outer_root = try state.stateRoot();
    const inner = try state.snapshot();
    try testing.expectError(error.InvalidSnapshot, state.commit(outer));
    try state.setStorage(address, 1, 2);
    _ = try state.setCode(address, "nested code");
    try state.revert(inner);
    try testing.expectEqualSlices(u8, &outer_root, &(try state.stateRoot()));
    try state.revert(outer);
    try testing.expectEqualSlices(u8, &empty_root, &(try state.stateRoot()));

    const parent_commit = try state.snapshot();
    try state.setNonce(address, 4);
    const child_commit = try state.snapshot();
    try state.setBalance(address, 6);
    try state.setStorage(address, 9, 10);
    _ = try state.setCode(address, "committed code");
    try state.commit(child_commit);
    const committed_root = try state.stateRoot();
    try state.revert(parent_commit);
    try testing.expectEqualSlices(u8, &empty_root, &(try state.stateRoot()));

    try state.setNonce(address, 4);
    try state.setBalance(address, 6);
    try state.setStorage(address, 9, 10);
    _ = try state.setCode(address, "committed code");
    const before_delete = try state.stateRoot();
    const delete_snapshot = try state.snapshot();
    try state.deleteAccount(address);
    try testing.expectEqualSlices(u8, &empty_root, &(try state.stateRoot()));
    try state.revert(delete_snapshot);
    try testing.expectEqualSlices(u8, &before_delete, &(try state.stateRoot()));
    try testing.expectEqualSlices(u8, &committed_root, &(try state.stateRoot()));
}

// Confirms blooms use only log addresses and topics, and combine receipt logs.
test "receipt blooms include addresses and topics but not data" {
    const logs = [_]execution.Log{.{ .address = .{0x11} ** 20, .topics = &.{.{0x22} ** 32}, .data = "ignored" }};
    const expected = execution.logsBloom(&logs);
    var filter = execution.bloom_filter.BloomFilter{ .bits = expected };
    try testing.expect(filter.mayContain(&logs[0].address));
    try testing.expect(filter.mayContain(&logs[0].topics[0]));
    try testing.expect(!filter.mayContain("ignored"));
    const receipt = execution.Receipt{ .legacy = .{ .status = 1, .cumulative_gas_used = 1, .logs_bloom = .{0} ** 256, .logs = &logs } };
    try testing.expectEqualSlices(u8, &expected, &execution.receiptsBloom(&.{receipt}));
}

// Matches the London fixture block's receipts trie root from its pinned header.
test "receipts root matches the pinned London sample block" {
    const receipt = execution.Receipt{ .legacy = .{ .status = 1, .cumulative_gas_used = 0xa861, .logs_bloom = .{0} ** 256, .logs = &.{} } };
    const root = try execution.receiptsRoot(testing.allocator, &.{receipt});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "c598f69a5674cae9337261b669970e24abc0b46e6d284372a239ec8ccbf20b0a");
    try testing.expectEqualSlices(u8, &expected, &root);
}

test "transaction envelopes round trip and fixed vectors" {
    const legacy = execution.Transaction{ .legacy = .{ .nonce = 0, .gas_price = 1, .gas_limit = 2, .to = null, .value = 3, .data = "", .v = 27, .r = 1, .s = 2 } };
    const access = execution.Transaction{ .access_list = .{ .chain_id = 1, .nonce = 0, .gas_price = 2, .gas_limit = 3, .to = null, .value = 4, .data = "", .access_list = &.{.{ .address = .{1} ** 20, .storage_keys = &.{.{2} ** 32} }}, .y_parity = 1, .r = 2, .s = 3 } };
    const dynamic = execution.Transaction{ .dynamic_fee = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 2, .max_fee_per_gas = 3, .gas_limit = 4, .to = null, .value = 5, .data = "a", .access_list = &.{}, .y_parity = 1, .r = 2, .s = 3 } };
    const blob = execution.Transaction{ .blob = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 2, .max_fee_per_gas = 3, .gas_limit = 4, .to = .{1} ** 20, .value = 5, .data = "", .access_list = &.{}, .max_fee_per_blob_gas = 6, .blob_versioned_hashes = &.{.{1} ** 32}, .y_parity = 1, .r = 2, .s = 3 } };
    const set_code = execution.Transaction{ .set_code = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 2, .max_fee_per_gas = 3, .gas_limit = 4, .destination = .{1} ** 20, .value = 5, .data = "", .access_list = &.{}, .authorization_list = &.{.{ .chain_id = 1, .address = .{2} ** 20, .nonce = 7, .y_parity = 1, .r = 8, .s = 9 }}, .y_parity = 1, .r = 2, .s = 3 } };
    for ([_]execution.Transaction{ legacy, access, dynamic, blob, set_code }) |tx| {
        const bytes = try execution.encode(testing.allocator, tx);
        defer testing.allocator.free(bytes);
        var decoded = try execution.parse(execution.Transaction, testing.allocator, bytes);
        defer decoded.deinit();
        const again = try execution.encode(testing.allocator, decoded.value);
        defer testing.allocator.free(again);
        try testing.expectEqualSlices(u8, bytes, again);
    }
    const bytes = try execution.encode(testing.allocator, legacy);
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0xc9, 0x80, 1, 2, 0x80, 3, 0x80, 27, 1, 2 }, bytes);
    const typed = try execution.encode(testing.allocator, dynamic);
    defer testing.allocator.free(typed);
    try testing.expectEqualSlices(u8, &.{ 2, 0xcc, 1, 0x80, 2, 3, 4, 0x80, 5, 0x61, 0xc0, 1, 2, 3 }, typed);
}

test "EIP-155 signed legacy transaction reference vector" {
    // https://eips.ethereum.org/EIPS/eip-155#example
    const hex = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    var buffer: [hex.len / 2]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&buffer, hex);
    var decoded = try execution.parse(execution.Transaction, testing.allocator, expected);
    defer decoded.deinit();
    try testing.expectEqual(@as(u64, 9), decoded.value.legacy.nonce);
    try testing.expectEqual(@as(u256, 37), decoded.value.legacy.v);
    const actual = try execution.encode(testing.allocator, decoded.value);
    defer testing.allocator.free(actual);
    try testing.expectEqualSlices(u8, expected, actual);
}

test "header, block, receipt, and withdrawal round trip" {
    const header = execution.Header{ .parent_hash = .{1} ** 32, .ommers_hash = .{2} ** 32, .fee_recipient = .{3} ** 20, .state_root = .{4} ** 32, .transactions_root = .{5} ** 32, .receipts_root = .{6} ** 32, .logs_bloom = .{7} ** 256, .difficulty = 0, .number = 8, .gas_limit = 9, .gas_used = 10, .timestamp = 11, .extra_data = "x", .prev_randao = .{12} ** 32, .nonce = .{0} ** 8, .base_fee_per_gas = (@as(u256, 1) << 200) + 13, .withdrawals_root = .{14} ** 32, .blob_gas_used = 15, .excess_blob_gas = 16, .parent_beacon_block_root = .{17} ** 32, .requests_hash = .{18} ** 32 };
    const withdrawal = execution.Withdrawal{ .index = 1, .validator_index = 2, .address = .{3} ** 20, .amount = 4 };
    const receipt = execution.Receipt{ .set_code = .{ .status = 1, .cumulative_gas_used = 2, .logs_bloom = .{0} ** 256, .logs = &.{.{ .address = .{3} ** 20, .topics = &.{.{4} ** 32}, .data = "x" }} } };
    const block = execution.Block{ .header = header, .transactions = &.{
        .{ .legacy = .{ .nonce = 0, .gas_price = 1, .gas_limit = 2, .to = null, .value = 3, .data = "", .v = 27, .r = 1, .s = 2 } },
        .{ .dynamic_fee = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 2, .max_fee_per_gas = 3, .gas_limit = 4, .to = null, .value = 5, .data = "", .access_list = &.{}, .y_parity = 1, .r = 2, .s = 3 } },
    }, .withdrawals = &.{withdrawal} };
    inline for (.{ header, withdrawal, receipt, block }) |item| {
        const bytes = try execution.encode(testing.allocator, item);
        defer testing.allocator.free(bytes);
        var decoded = try execution.parse(@TypeOf(item), testing.allocator, bytes);
        defer decoded.deinit();
        const again = try execution.encode(testing.allocator, decoded.value);
        defer testing.allocator.free(again);
        try testing.expectEqualSlices(u8, bytes, again);
    }
    const receipt_variants = [_]execution.Receipt{
        .{ .legacy = receipt.set_code },
        .{ .access_list = receipt.set_code },
        .{ .dynamic_fee = receipt.set_code },
        .{ .blob = receipt.set_code },
        .{ .set_code = receipt.set_code },
    };
    for (receipt_variants) |variant| {
        const bytes = try execution.encode(testing.allocator, variant);
        defer testing.allocator.free(bytes);
        var decoded = try execution.parse(execution.Receipt, testing.allocator, bytes);
        defer decoded.deinit();
        const again = try execution.encode(testing.allocator, decoded.value);
        defer testing.allocator.free(again);
        try testing.expectEqualSlices(u8, bytes, again);
    }
    const wd = try execution.encode(testing.allocator, withdrawal);
    defer testing.allocator.free(wd);
    try testing.expectEqualSlices(u8, &([_]u8{ 0xd8, 1, 2, 0x94 } ++ [_]u8{3} ** 20 ++ [_]u8{4}), wd);
    const header_bytes = try execution.encode(testing.allocator, header);
    defer testing.allocator.free(header_bytes);
    var tree = try rlp.decode.decodeAll(testing.allocator, header_bytes);
    defer tree.deinit(testing.allocator);
    const fields = tree.list;
    try testing.expectEqual(@as(usize, 21), fields.len);
    try testing.expectEqualSlices(u8, &.{8}, fields[8].string); // number follows difficulty
    try testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, fields[15].string[0..8]);
    try testing.expectEqual(@as(usize, 26), fields[15].string.len); // base fee exceeds 64 bits
    try testing.expectEqualSlices(u8, &([_]u8{18} ** 32), fields[20].string); // requests hash is last
    const block_bytes = try execution.encode(testing.allocator, block);
    defer testing.allocator.free(block_bytes);
    var block_tree = try rlp.decode.decodeAll(testing.allocator, block_bytes);
    defer block_tree.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), block_tree.list[2].list.len);
    try testing.expectEqual(@as(u8, 2), block_tree.list[1].list[1].string[0]);
}

test "reject invalid transaction envelopes and field shapes" {
    try testing.expectError(error.UnknownTransactionType, execution.parse(execution.Transaction, testing.allocator, &.{5}));
    try testing.expectError(error.UnknownTransactionType, execution.parse(execution.Transaction, testing.allocator, &.{0}));
    try testing.expectError(error.UnknownTransactionType, execution.parse(execution.Receipt, testing.allocator, &.{5}));
    for ([_][]const u8{ &.{ 2, 0xc0 }, &.{0xc0} }) |bytes| {
        try testing.expectError(error.InvalidShape, execution.parse(execution.Transaction, testing.allocator, bytes));
    }
    try testing.expectError(error.TrailingBytes, execution.parse(execution.Transaction, testing.allocator, &.{ 2, 0xc0, 0x80 }));
    try testing.expectError(error.Truncated, execution.parse(execution.Transaction, testing.allocator, &.{ 0xc9, 0x80, 1 }));
    try testing.expectError(error.TrailingBytes, execution.parse(execution.Transaction, testing.allocator, &.{ 0xc9, 0x80, 1, 2, 0x80, 3, 0x80, 27, 1, 2, 0x80 }));
    try testing.expectError(error.InvalidLength, execution.parse(execution.Withdrawal, testing.allocator, &([_]u8{ 0xd7, 1, 2, 0x93 } ++ [_]u8{3} ** 19 ++ [_]u8{4})));
    try testing.expectError(error.InvalidShape, execution.parse(execution.Withdrawal, testing.allocator, &.{0xc0}));
    try testing.expectError(error.InvalidLength, execution.parse(execution.Transaction, testing.allocator, &.{ 0xc9, 0x80, 1, 2, 1, 3, 0x80, 27, 1, 2 }));
    try testing.expectError(error.InvalidLength, execution.parse(execution.Receipt, testing.allocator, &.{ 0xc4, 1, 2, 0x80, 0xc0 }));
}

test "Cancun and Prague system calls update roots before block commitment" {
    const a = testing.allocator;
    const beacon_address: execution.Address = .{ 0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22, 0xd0, 0xbe, 0xac, 0x02 };
    const history_address: execution.Address = .{ 0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35 };
    const beacon_hex = "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500";
    const history_hex = "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500";
    var beacon_code: [beacon_hex.len / 2]u8 = undefined;
    var history_code: [history_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&beacon_code, beacon_hex);
    _ = try std.fmt.hexToBytes(&history_code, history_hex);
    for ([_]execution.transition.Fork{ .cancun, .prague, .osaka }) |fork| {
        var world = execution.state.State.init(a);
        defer world.deinit();
        _ = try world.setCode(beacon_address, &beacon_code);
        _ = try world.setCode(history_address, &history_code);
        var parent = std.mem.zeroes(execution.Header);
        parent.gas_limit = 30_000_000;
        parent.base_fee_per_gas = 1;
        parent.state_root = try world.stateRoot();
        var header = parent;
        header.parent_hash = try execution.transition.headerHash(a, fork, parent);
        header.number = 1;
        header.timestamp = 12;
        header.parent_beacon_block_root = .{0x42} ** 32;
        header.transactions_root = try execution.trie.orderedRoot(a, &.{});
        header.receipts_root = try execution.receiptsRoot(a, &.{});
        header.withdrawals_root = try execution.trie.orderedRoot(a, &.{});
        var trial = try world.clone(a);
        defer trial.deinit();
        try execution.transition.applySystemTransitions(a, &trial, .{ .fork = fork, .chain_id = 1, .coinbase = header.fee_recipient, .number = 1, .timestamp = 12, .gas_limit = header.gas_limit, .base_fee = header.base_fee_per_gas, .blob_base_fee = 1 }, header.parent_hash, header.parent_beacon_block_root);
        header.state_root = try trial.stateRoot();
        try testing.expectEqual(@as(u256, 0), world.getStorage(beacon_address, 12));
        var invalid = header;
        invalid.state_root = parent.state_root;
        try testing.expectError(error.InvalidCommitment, execution.transition.applyBlock(a, &world, .{ .fork = fork, .parent_fork = fork, .chain_id = 1 }, parent, invalid, &.{}, &.{}));
        try testing.expectEqualSlices(u8, &parent.state_root, &(try world.stateRoot()));
        var result = try execution.transition.applyBlock(a, &world, .{ .fork = fork, .parent_fork = fork, .chain_id = 1 }, parent, header, &.{}, &.{});
        defer result.deinit();
        try testing.expectEqualSlices(u8, &header.state_root, &(try world.stateRoot()));
        try testing.expectEqual(@as(u256, 12), world.getStorage(beacon_address, 12));
        try testing.expectEqual(std.mem.readInt(u256, &header.parent_beacon_block_root, .big), world.getStorage(beacon_address, 8191 + 12));
        try testing.expectEqual(if (fork == .cancun) @as(u256, 0) else std.mem.readInt(u256, &header.parent_hash, .big), world.getStorage(history_address, 0));
    }
}
