// A transaction envelope is its typed RLP payload; a fork is the rule-set
// revision used to select a fixture's expected result. These cases validate
// checksums and JSON fields before decoding, and check canonical RLP bytes only.
// State tests compare before/after world state, but this harness applies none.
// State and blockchain execution processors remain outside the supported scope.
//
// source JSON -> checksum/schema validation -> transaction decode -> re-encode
//                                   └──── state/blockchain cases are reported skipped
const std = @import("std");
const execution = @import("execution");

const Format = enum { transaction, state, blockchain };
const Outcome = enum { valid, InvalidLength, NonCanonicalInteger, skip };

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
    .{ .name = "chainid_cancun_state_test_tx_type_0", .format = "state", .fork = "Cancun", .expected = .skip, .skip_reason = "state transition processor is tracked separately", .checksum = "adbab28513ccf33a4e0c2bc79b19ebf341f93a64d75238d95cb4f6c8b9ce55a6", .bytes = @embedFile("fixtures/chainid_cancun_state_test_tx_type_0.json") },
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

    if (format == .state or format == .blockchain) {
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
    const encoded = try execution.encode(allocator, decoded.value);
    defer allocator.free(encoded);
    if (!std.mem.eql(u8, raw, encoded)) return error.RoundTripMismatch;
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
    try std.testing.expectEqual(@as(usize, 4), counts.passed);
    try std.testing.expectEqual(@as(usize, 2), counts.skipped);
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
