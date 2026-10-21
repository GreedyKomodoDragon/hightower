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
