// Transaction fixtures check canonical envelopes. State fixtures select one
// fork and transaction index, then compare account fields, the state trie root,
// and the hash of ordered EVM logs. Invalid transactions leave pre-state intact.
//
// JSON -> selected transaction -> state transition -> oracle fields
// Blockchain fixture processing remains in FULU-062.
const std = @import("std");
const execution = @import("execution");

const Format = enum { transaction, state, blockchain };
const Outcome = enum { valid, InvalidLength, NonCanonicalInteger, invalid_transaction, skip };

const Fixture = struct {
    name: []const u8,
    format: []const u8,
    fork: []const u8,
    expected: ?Outcome,
    skip_reason: ?[]const u8 = null,
    checksum: []const u8,
    bytes: []const u8,
};

const fixtures = [_]Fixture{
    .{ .name = "accessListStorage32Bytes", .format = "transaction", .fork = "Cancun", .expected = .valid, .checksum = "02650cf49ea0034cf882a32e4ffcbb45b96ee5fd1e38d5c11e31f0f247ce966e", .bytes = @embedFile("fixtures/accessListStorage32Bytes.json") },
    .{ .name = "AddressLessThan20", .format = "transaction", .fork = "Cancun", .expected = .InvalidLength, .checksum = "73e22320caea3169610f13b3abbfdc1240010b5d219877fbfe14826cc7113e7f", .bytes = @embedFile("fixtures/AddressLessThan20.json") },
    .{ .name = "maxFeePerGas00prefix", .format = "transaction", .fork = "Cancun", .expected = .NonCanonicalInteger, .checksum = "20389c8758b06db2509b4b854657cabe97b839bdff37e53e102b4118a65baaa6", .bytes = @embedFile("fixtures/maxFeePerGas00prefix.json") },
    .{ .name = "tx_simple_type_0_shanghai", .format = "transaction", .fork = "Shanghai", .expected = .valid, .checksum = "57c9c3cd9086ea34f82befd3f88013cef7829d975450ae35055493001269e068", .bytes = @embedFile("fixtures/tx_simple_type_0_shanghai.json") },
    .{ .name = "chainid_cancun_state_test_tx_type_0", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "adbab28513ccf33a4e0c2bc79b19ebf341f93a64d75238d95cb4f6c8b9ce55a6", .bytes = @embedFile("fixtures/chainid_cancun_state_test_tx_type_0.json") },
    .{ .name = "invalidTr", .format = "state", .fork = "Cancun", .expected = .invalid_transaction, .checksum = "2bce278411aaba2b37a18ee6ed04ae0925ece8e0326358edb0eba5b4157e2264", .bytes = @embedFile("fixtures/invalidTr.json") },
    .{ .name = "chainid_london_blockchain_test_tx_type_0", .format = "blockchain", .fork = "London", .expected = .skip, .skip_reason = "blockchain test processor is tracked separately", .checksum = "934a836ca8a7d203d3e5388f7ea37a3a4a210954ecfb8b5f64b46ba79db57af3", .bytes = @embedFile("fixtures/chainid_london_blockchain_test_tx_type_0.json") },
};

const Counts = struct { passed: usize = 0, skipped: usize = 0 };

/// Checks a 64-character lowercase SHA-256 string against the fixture bytes.
fn checksumMatches(bytes: []const u8, expected: []const u8) bool {
    if (expected.len != 64) return false;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const digits = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        if (expected[i * 2] != digits[byte >> 4] or expected[i * 2 + 1] != digits[byte & 0x0f]) return false;
    }
    return true;
}

/// Returns a required object member or rejects malformed fixture structure.
fn member(value: std.json.Value, key: []const u8) error{MissingField}!std.json.Value {
    if (value != .object) return error.MissingField;
    return value.object.get(key) orelse error.MissingField;
}

/// Requires a non-empty JSON string at the selected member.
fn stringMember(value: std.json.Value, key: []const u8) error{MissingField}![]const u8 {
    const field = try member(value, key);
    if (field != .string or field.string.len == 0) return error.MissingField;
    return field.string;
}

/// Converts fixture hex data to bytes, rejecting prefixes, odd lengths, and bad digits.
fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len < 2 or !std.mem.startsWith(u8, hex, "0x") or (hex.len - 2) % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, (hex.len - 2) / 2);
    errdefer allocator.free(out);
    for (out, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[2 + i * 2 ..][0..2], 16) catch return error.InvalidHex;
    }
    return out;
}

/// Validates the source oracle fields and returns transaction bytes for transaction fixtures.
fn transactionBytes(allocator: std.mem.Allocator, root: std.json.Value, fixture: Fixture) ![]u8 {
    const test_value = if (root == .object and root.object.count() == 1) root.object.values()[0] else return error.MissingField;
    const hex = try stringMember(test_value, "txbytes");
    const result = try member(test_value, "result");
    const fork_result = try member(result, fixture.fork);
    if (fixture.expected == .InvalidLength or fixture.expected == .NonCanonicalInteger) {
        const exception = try stringMember(fork_result, "exception");
        const expected_exception = if (fixture.expected == .InvalidLength) "TransactionException.ADDRESS_TOO_SHORT" else "TransactionException.RLP_LEADING_ZEROS_BASEFEE";
        if (!std.mem.eql(u8, exception, expected_exception)) return error.MissingExpectation;
    } else {
        _ = try member(fork_result, "intrinsicGas");
    }
    return decodeHex(allocator, hex);
}

/// Checks state and blockchain fixture oracle fields before a deliberate skip.
fn validateSkipped(root: std.json.Value, fixture: Fixture) !void {
    const test_value = if (root == .object and root.object.count() == 1) root.object.values()[0] else return error.MissingField;
    const info = try member(test_value, "_info");
    const source_format = try stringMember(info, "fixture_format");
    if (std.mem.eql(u8, fixture.format, "state")) {
        if (!std.mem.eql(u8, source_format, "state_test")) return error.MissingField;
        _ = try member(test_value, "transaction");
        _ = try member(try member(test_value, "post"), fixture.fork);
    } else {
        if (!std.mem.eql(u8, source_format, "blockchain_test")) return error.MissingField;
        _ = try member(test_value, "blocks");
        _ = try member(test_value, "postState");
        _ = try stringMember(test_value, "lastblockhash");
    }
}

/// Validates and runs one fixture, returning whether it passed or was skipped.
fn runFixture(allocator: std.mem.Allocator, fixture: Fixture, bytes: []const u8) !bool {
    if (fixture.expected == null) return error.MissingExpectation;
    if (!checksumMatches(bytes, fixture.checksum)) return error.ChecksumMismatch;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return error.MalformedJson;
    defer parsed.deinit();
    const format = std.meta.stringToEnum(Format, fixture.format) orelse return error.UnknownFormat;

    if (format == .state) {
        if (fixture.expected.? == .skip) {
            if (fixture.skip_reason == null) return error.MissingExpectation;
            try validateSkipped(parsed.value, fixture);
            return false;
        }
        return runStateFixture(allocator, parsed.value, fixture);
    }
    if (format == .blockchain) {
        if (fixture.expected.? != .skip or fixture.skip_reason == null) return error.MissingExpectation;
        try validateSkipped(parsed.value, fixture);
        return false;
    }
    if (fixture.expected.? == .skip) return error.MissingExpectation;
    const raw = try transactionBytes(allocator, parsed.value, fixture);
    defer allocator.free(raw);
    var decoded = execution.parse(execution.Transaction, allocator, raw) catch |err| {
        const expected_error: ?anyerror = switch (fixture.expected.?) {
            .InvalidLength => error.InvalidLength,
            .NonCanonicalInteger => error.NonCanonicalInteger,
            else => null,
        };
        if (expected_error != null and err == expected_error.?) return true;
        std.debug.print("FAIL {s}: transaction decode returned {s}\n", .{ fixture.name, @errorName(err) });
        return err;
    };
    defer decoded.deinit();
    if (fixture.expected.? != .valid) return error.UnexpectedSuccess;
    const canonical = try execution.encode(allocator, decoded.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, raw, canonical)) return error.RoundTripMismatch;
    return true;
}

/// Runs the fixed manifest and counts validated cases and named processor skips.
pub fn run(allocator: std.mem.Allocator) !Counts {
    var counts: Counts = .{};
    for (fixtures) |fixture| {
        if (try runFixture(allocator, fixture, fixture.bytes)) {
            counts.passed += 1;
        } else {
            counts.skipped += 1;
            std.debug.print("SKIP {s}: {s}\n", .{ fixture.name, fixture.skip_reason.? });
        }
    }
    return counts;
}

test "pinned execution fixtures pass and unsupported processors are explicit" {
    const counts = try run(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 6), counts.passed);
    try std.testing.expectEqual(@as(usize, 1), counts.skipped);
    std.debug.print("execution fixtures: {d} passed, {d} skipped\n", .{ counts.passed, counts.skipped });
}

test "rejects checksum mismatch, malformed JSON, missing expectation, and unknown format" {
    try std.testing.expect(!checksumMatches("{}", "0000000000000000000000000000000000000000000000000000000000000000"));
    var fixture = fixtures[0];
    fixture.checksum = "0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expectError(error.ChecksumMismatch, runFixture(std.testing.allocator, fixture, "{}"));

    fixture.checksum = "021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96";
    try std.testing.expectError(error.MalformedJson, runFixture(std.testing.allocator, fixture, "{"));

    fixture.expected = null;
    try std.testing.expectError(error.MissingExpectation, runFixture(std.testing.allocator, fixture, fixtures[0].bytes));

    fixture.expected = .valid;
    fixture.fork = "UnknownFork";
    fixture.checksum = fixtures[0].checksum;
    try std.testing.expectError(error.MissingField, runFixture(std.testing.allocator, fixture, fixtures[0].bytes));

    fixture.format = "future_format";
    fixture.fork = fixtures[0].fork;
    fixture.checksum = fixtures[0].checksum;
    try std.testing.expectError(error.UnknownFormat, runFixture(std.testing.allocator, fixture, fixtures[0].bytes));
}

/// Parses a required 0x-prefixed fixture quantity without accepting omitted values.
fn quantity(value: std.json.Value) !u256 {
    if (value != .string or !std.mem.startsWith(u8, value.string, "0x") or value.string.len < 3) return error.InvalidQuantity;
    return std.fmt.parseInt(u256, value.string[2..], 16) catch error.InvalidQuantity;
}

/// Decodes a required fixed-size hash or address.
fn fixedHex(comptime N: usize, allocator: std.mem.Allocator, value: std.json.Value) ![N]u8 {
    if (value != .string) return error.InvalidHex;
    const bytes = try decodeHex(allocator, value.string);
    defer allocator.free(bytes);
    if (bytes.len != N) return error.InvalidHex;
    return bytes[0..N].*;
}

/// Loads each pre-account, including code and storage, into the execution state.
fn loadAccounts(allocator: std.mem.Allocator, world: *execution.state.State, accounts: std.json.Value) !void {
    if (accounts != .object) return error.MissingField;
    var it = accounts.object.iterator();
    while (it.next()) |entry| {
        const address = try fixedHex(20, allocator, .{ .string = entry.key_ptr.* });
        const item = entry.value_ptr.*;
        try world.createAccount(address);
        try world.setNonce(address, @intCast(try quantity(try member(item, "nonce"))));
        try world.setBalance(address, try quantity(try member(item, "balance")));
        const code = try decodeHex(allocator, try stringMember(item, "code"));
        defer allocator.free(code);
        _ = try world.setCode(address, code);
        const storage = try member(item, "storage");
        if (storage != .object) return error.MissingField;
        var slots = storage.object.iterator();
        while (slots.next()) |slot| try world.setStorage(address, try quantity(.{ .string = slot.key_ptr.* }), try quantity(slot.value_ptr.*));
    }
}

/// Compares every declared post-account field and rejects undeclared extra accounts.
fn checkAccounts(allocator: std.mem.Allocator, world: *execution.state.State, accounts: std.json.Value) !void {
    if (accounts != .object or world.accounts.items.len != accounts.object.count()) return error.StateMismatch;
    var it = accounts.object.iterator();
    while (it.next()) |entry| {
        const address = try fixedHex(20, allocator, .{ .string = entry.key_ptr.* });
        const item = entry.value_ptr.*;
        const account = (try world.getAccount(address)) orelse return error.StateMismatch;
        if (account.nonce != try quantity(try member(item, "nonce")) or account.balance != try quantity(try member(item, "balance"))) return error.StateMismatch;
        const code = try decodeHex(allocator, try stringMember(item, "code"));
        defer allocator.free(code);
        if (!std.mem.eql(u8, world.getCode(address), code)) return error.StateMismatch;
        const storage = try member(item, "storage");
        if (storage != .object) return error.MissingField;
        var slots = storage.object.iterator();
        while (slots.next()) |slot| {
            if (world.getStorage(address, try quantity(.{ .string = slot.key_ptr.* })) != try quantity(slot.value_ptr.*)) return error.StateMismatch;
        }
        for (world.accounts.items) |actual| {
            if (!std.mem.eql(u8, &actual.address, &address)) continue;
            if (actual.storage.items.len != storage.object.count()) return error.StateMismatch;
        }
    }
}

/// Returns the fixture field chosen by a required transaction index.
fn selectedValue(transaction: std.json.Value, indexes: std.json.Value, key: []const u8, field: []const u8) ![]const u8 {
    const index = try member(indexes, key);
    const values = try member(transaction, field);
    if (index != .integer or index.integer < 0 or values != .array or @as(usize, @intCast(index.integer)) >= values.array.items.len) return error.MissingExpectation;
    const selected = values.array.items[@intCast(index.integer)];
    if (selected != .string) return error.MissingExpectation;
    return selected.string;
}

/// Runs a selected fork outcome against transaction bytes, full state, root, and logs hash.
fn runStateFixture(allocator: std.mem.Allocator, root: std.json.Value, fixture: Fixture) !bool {
    const test_value = if (root == .object and root.object.count() == 1) root.object.values()[0] else return error.MissingField;
    const info = try member(test_value, "_info");
    const format_name = if (info == .object and info.object.contains("fixture_format")) "fixture_format" else "fixture-format";
    if (!std.mem.eql(u8, try stringMember(info, format_name), "state_test")) return error.MissingField;
    const post = try member(try member(test_value, "post"), fixture.fork);
    if (post != .array or post.array.items.len != 1) return error.MissingExpectation;
    const expected = post.array.items[0];
    const indexes = try member(expected, "indexes");
    const transaction = try member(test_value, "transaction");
    const raw = try decodeHex(allocator, try stringMember(expected, "txbytes"));
    defer allocator.free(raw);
    var decoded = try execution.parse(execution.Transaction, allocator, raw);
    defer decoded.deinit();
    const selected_gas = try selectedValue(transaction, indexes, "gas", "gasLimit");
    const selected_data = try selectedValue(transaction, indexes, "data", "data");
    const selected_value = try selectedValue(transaction, indexes, "value", "value");
    const legacy = switch (decoded.value) {
        .legacy => |tx| tx,
        else => return error.TransactionMismatch,
    };
    const expected_to = try fixedHex(20, allocator, try member(transaction, "to"));
    const actual_to = legacy.to orelse return error.TransactionMismatch;
    const expected_data = try decodeHex(allocator, selected_data);
    defer allocator.free(expected_data);
    if (legacy.nonce != try quantity(try member(transaction, "nonce")) or
        legacy.gas_limit != try quantity(.{ .string = selected_gas }) or
        legacy.gas_price != try quantity(try member(transaction, "gasPrice")) or
        legacy.value != try quantity(.{ .string = selected_value }) or
        !std.mem.eql(u8, &actual_to, &expected_to) or
        !std.mem.eql(u8, legacy.data, expected_data)) return error.TransactionMismatch;
    const canonical = try execution.encode(allocator, decoded.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, raw, canonical)) return error.TransactionMismatch;
    const sender = try execution.recoverSender(allocator, decoded.value, try quantity(try member(try member(test_value, "config"), "chainid")));
    const expected_sender = try fixedHex(20, allocator, try member(transaction, "sender"));
    if (!std.mem.eql(u8, &sender, &expected_sender)) return error.TransactionMismatch;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    try loadAccounts(allocator, &world, try member(test_value, "pre"));
    const env = try member(test_value, "env");
    const config = try member(test_value, "config");
    const fork = if (std.mem.eql(u8, fixture.fork, "Cancun")) execution.transition.Fork.cancun else if (std.mem.eql(u8, fixture.fork, "London")) execution.transition.Fork.london else null orelse return error.UnsupportedFork;
    const context: execution.transition.Context = .{
        .fork = fork,
        .chain_id = try quantity(try member(config, "chainid")),
        .coinbase = try fixedHex(20, allocator, try member(env, "currentCoinbase")),
        .number = @intCast(try quantity(try member(env, "currentNumber"))),
        .timestamp = @intCast(try quantity(try member(env, "currentTimestamp"))),
        .gas_limit = @intCast(try quantity(try member(env, "currentGasLimit"))),
        .base_fee = try quantity(try member(env, "currentBaseFee")),
        .prev_randao = try fixedHex(32, allocator, try member(env, "currentRandom")),
        .blob_base_fee = if (try quantity(try member(env, "currentExcessBlobGas")) == 0) 1 else null,
    };
    if (fixture.expected == .invalid_transaction) {
        if (!std.mem.eql(u8, try stringMember(expected, "expectException"), "TransactionException.INTRINSIC_GAS_TOO_LOW")) return error.MissingExpectation;
        if (execution.transition.applyTransaction(allocator, &world, context, raw, context.gas_limit, 0)) |outcome| {
            var owned = outcome;
            owned.deinit();
            return error.UnexpectedSuccess;
        } else |err| {
            if (err != error.IntrinsicGasTooLow) return err;
        }
        try checkAccounts(allocator, &world, try member(expected, "state"));
        const expected_root = try fixedHex(32, allocator, try member(expected, "hash"));
        const actual_root = try world.stateRoot();
        if (!std.mem.eql(u8, &expected_root, &actual_root)) return error.StateRootMismatch;
        const empty_logs = try execution.encode(allocator, @as([]const execution.Log, &.{}));
        defer allocator.free(empty_logs);
        var logs_hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(empty_logs, &logs_hash, .{});
        const expected_logs = try fixedHex(32, allocator, try member(expected, "logs"));
        if (!std.mem.eql(u8, &expected_logs, &logs_hash)) return error.LogsHashMismatch;
    } else {
        if (expected == .object and expected.object.contains("expectException")) return error.MissingExpectation;
        var outcome = try execution.transition.applyTransaction(allocator, &world, context, raw, context.gas_limit, 0);
        defer outcome.deinit();
        try checkAccounts(allocator, &world, try member(expected, "state"));
        const root_hash = try fixedHex(32, allocator, try member(expected, "hash"));
        if (!std.mem.eql(u8, &root_hash, &(try world.stateRoot()))) return error.StateRootMismatch;
        const logs = switch (outcome.receipt) {
            inline else => |payload| payload.logs,
        };
        const encoded = try execution.encode(allocator, logs);
        defer allocator.free(encoded);
        var logs_hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(encoded, &logs_hash, .{});
        const expected_logs = try fixedHex(32, allocator, try member(expected, "logs"));
        if (!std.mem.eql(u8, &expected_logs, &logs_hash)) return error.LogsHashMismatch;
    }
    return true;
}

// The London block fixture is a targeted oracle here; full blockchain fixture
// processing (including RLP block traversal) belongs to FULU-062.
test "London block transition matches pinned state and receipt commitments" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixtures[6].bytes, .{});
    defer parsed.deinit();
    const test_value = parsed.value.object.values()[0];
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    try loadAccounts(allocator, &world, try member(test_value, "pre"));
    const parent_json = try member(test_value, "genesisBlockHeader");
    const blocks = try member(test_value, "blocks");
    const block_json = blocks.array.items[0];
    const header_json = try member(block_json, "blockHeader");
    var parent: execution.Header = std.mem.zeroes(execution.Header);
    parent.number = @intCast(try quantity(try member(parent_json, "number")));
    parent.timestamp = @intCast(try quantity(try member(parent_json, "timestamp")));
    parent.gas_limit = @intCast(try quantity(try member(parent_json, "gasLimit")));
    parent.gas_used = @intCast(try quantity(try member(parent_json, "gasUsed")));
    parent.base_fee_per_gas = try quantity(try member(parent_json, "baseFeePerGas"));
    var header: execution.Header = std.mem.zeroes(execution.Header);
    header.number = @intCast(try quantity(try member(header_json, "number")));
    header.timestamp = @intCast(try quantity(try member(header_json, "timestamp")));
    header.gas_limit = @intCast(try quantity(try member(header_json, "gasLimit")));
    header.gas_used = @intCast(try quantity(try member(header_json, "gasUsed")));
    header.base_fee_per_gas = try quantity(try member(header_json, "baseFeePerGas"));
    header.fee_recipient = try fixedHex(20, allocator, try member(header_json, "coinbase"));
    header.state_root = try fixedHex(32, allocator, try member(header_json, "stateRoot"));
    header.transactions_root = try fixedHex(32, allocator, try member(header_json, "transactionsTrie"));
    header.receipts_root = try fixedHex(32, allocator, try member(header_json, "receiptTrie"));
    header.logs_bloom = try fixedHex(256, allocator, try member(header_json, "bloom"));
    const state_fixture = try std.json.parseFromSlice(std.json.Value, allocator, fixtures[4].bytes, .{});
    defer state_fixture.deinit();
    const state_case = state_fixture.value.object.values()[0];
    const post = try member(try member(state_case, "post"), "Cancun");
    const tx = try decodeHex(allocator, try stringMember(post.array.items[0], "txbytes"));
    defer allocator.free(tx);
    var result = try execution.transition.applyBlock(allocator, &world, .london, 1, parent, header, &.{tx}, &.{});
    defer result.deinit();
    try std.testing.expectEqual(@as(u64, 0xa861), result.gas_used);
    try checkAccounts(allocator, &world, try member(test_value, "postState"));
}

/// Builds the pinned valid state fixture's pre-state and transaction input.
fn sampleTransaction(allocator: std.mem.Allocator, world: *execution.state.State) !struct { raw: []u8, context: execution.transition.Context } {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixtures[4].bytes, .{});
    defer parsed.deinit();
    const test_value = parsed.value.object.values()[0];
    try loadAccounts(allocator, world, try member(test_value, "pre"));
    const post = try member(try member(test_value, "post"), "Cancun");
    const raw = try decodeHex(allocator, try stringMember(post.array.items[0], "txbytes"));
    const env = try member(test_value, "env");
    return .{ .raw = raw, .context = .{
        .fork = .cancun,
        .chain_id = 1,
        .coinbase = try fixedHex(20, allocator, try member(env, "currentCoinbase")),
        .number = 1,
        .timestamp = 1000,
        .gas_limit = @intCast(try quantity(try member(env, "currentGasLimit"))),
        .base_fee = 7,
    } };
}

test "transaction prechecks preserve state and gas refund is capped" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const sender: execution.Address = try fixedHex(20, allocator, .{ .string = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" });
    const recipient: execution.Address = try fixedHex(20, allocator, .{ .string = "0x1000000000000000000000000000000000000000" });
    const root = try world.stateRoot();
    try world.setNonce(sender, 1);
    try std.testing.expectError(error.InvalidNonce, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try world.setNonce(sender, 0);
    try world.setBalance(sender, 0);
    try std.testing.expectError(error.InsufficientBalance, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try world.setBalance(sender, 1_000_000_000_000_000_000_000);
    try std.testing.expectError(error.BlockGasLimitExceeded, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, 99_999_999, 0));
    var expensive = sample.context;
    expensive.base_fee = 11;
    try std.testing.expectError(error.InvalidFee, execution.transition.applyTransaction(allocator, &world, expensive, sample.raw, sample.context.gas_limit, 0));
    try std.testing.expectEqualSlices(u8, &root, &(try world.stateRoot()));
    const exact = try world.snapshot();
    var exact_outcome = try execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, 100_000_000, 0);
    exact_outcome.deinit();
    try world.revert(exact);
    try std.testing.expectEqualSlices(u8, &root, &(try world.stateRoot()));
    // Clearing an occupied slot earns a refund; the receipt remains owned after Machine.deinit.
    try world.setStorage(recipient, 1, 1);
    _ = try world.setCode(recipient, &.{ 0x60, 0, 0x60, 1, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0x00 });
    var outcome = try execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0);
    defer outcome.deinit();
    const payload = outcome.receipt.legacy;
    try std.testing.expectEqual(@as(u8, 1), payload.status);
    try std.testing.expectEqual(@as(usize, 1), payload.logs.len);
    try std.testing.expectEqualSlices(u8, &recipient, &payload.logs[0].address);
    try std.testing.expect(outcome.gas_used < 25_000);
    const after = try world.stateRoot();
    try world.setNonce(sender, 2);
    try std.testing.expectError(error.InvalidNonce, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try world.setNonce(sender, 1);
    try std.testing.expectEqualSlices(u8, &after, &(try world.stateRoot()));
}

test "block commitment failure rolls back transactions and withdrawals" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const original = try world.stateRoot();
    var parent: execution.Header = std.mem.zeroes(execution.Header);
    parent.gas_limit = sample.context.gas_limit;
    parent.base_fee_per_gas = 7;
    var header: execution.Header = std.mem.zeroes(execution.Header);
    header.number = 1;
    header.timestamp = 1000;
    header.gas_limit = parent.gas_limit;
    header.base_fee_per_gas = 7;
    header.gas_used = 0xa861;
    header.fee_recipient = sample.context.coinbase;
    header.gas_limit = parent.gas_limit + parent.gas_limit / 1024;
    try std.testing.expectError(error.InvalidGasLimit, execution.transition.applyBlock(allocator, &world, .london, 1, parent, header, &.{sample.raw}, &.{}));
    header.gas_limit = parent.gas_limit;
    header.base_fee_per_gas = 8;
    try std.testing.expectError(error.InvalidBaseFee, execution.transition.applyBlock(allocator, &world, .london, 1, parent, header, &.{sample.raw}, &.{}));
    header.base_fee_per_gas = 7;
    try std.testing.expectError(error.InvalidCommitment, execution.transition.applyBlock(allocator, &world, .london, 1, parent, header, &.{sample.raw}, &.{}));
    try std.testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
    const destination: execution.Address = .{9} ** 20;
    const withdrawal: execution.Withdrawal = .{ .index = 0, .validator_index = 0, .address = destination, .amount = 3 };
    header.gas_used = 0;
    const empty = try execution.trie.orderedRoot(allocator, &.{});
    header.transactions_root = empty;
    header.receipts_root = empty;
    const withdrawal_bytes = try execution.encode(allocator, withdrawal);
    defer allocator.free(withdrawal_bytes);
    header.withdrawals_root = try execution.trie.orderedRoot(allocator, &.{withdrawal_bytes});
    const snapshot = try world.snapshot();
    try world.setBalance(destination, 3_000_000_000);
    header.state_root = try world.stateRoot();
    try world.revert(snapshot);
    var result = try execution.transition.applyBlock(allocator, &world, .cancun, 1, parent, header, &.{}, &.{withdrawal});
    defer result.deinit();
    try std.testing.expectEqual(@as(u256, 3_000_000_000), world.getBalance(destination));
}

test "unsupported precompile nested in a transaction rolls back" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const recipient: execution.Address = try fixedHex(20, allocator, .{ .string = "0x1000000000000000000000000000000000000000" });
    _ = try world.setCode(recipient, &.{ 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 1, 0x61, 0xff, 0xff, 0xfa, 0x00 });
    const original = try world.stateRoot();
    try std.testing.expectError(error.UnsupportedExecution, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try std.testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
}
