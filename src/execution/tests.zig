// Execution RLP fixtures exercise ordered Fulu fields and all supported
// transaction envelopes. Encoded bytes are consensus-critical because changing
// even one field position changes the transaction or block hash.
const std = @import("std");
const execution = @import("execution");
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
        if (std.mem.eql(u8, &address, &expected)) recovered = true;
    }
    try testing.expect(recovered);
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
