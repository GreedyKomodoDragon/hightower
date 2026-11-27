// These pinned EVM vectors check bytecode execution against published EIP
// examples. SSTORE rows start from a transaction-original slot value; Fulu
// adds the first cold-slot charge to EIP-3529's reduced-refund test table.
// MCOPY rows start with EIP-5656 memory images and compare the copied bytes.
// The fixture runner executes one call frame, then checks gas and state.
//
// source examples → Fulu gas expectations → interpreter → output/state
const std = @import("std");
const execution = @import("execution");
const evm = @import("execution").evm;
const state = @import("execution").state;

const SStoreCase = struct {
    name: []const u8,
    initial_slot: u256,
    code: []const u8,
    gas_used: u64,
    refund: i128,
    final_slot: u256,
};
const MCopyCase = struct {
    name: []const u8,
    pre: []const u8,
    dst: u8,
    src: u8,
    length: u8,
    expected: []const u8,
    gas_used: u64,
};
const Fixture = struct {
    sstore_source: []const u8,
    mcopy_source: []const u8,
    rules: []const u8,
    sstore: []SStoreCase,
    mcopy: []MCopyCase,
};

/// Decodes a fixture's even-length hexadecimal bytes, with an optional 0x prefix.
fn hexBytes(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const hex = if (std.mem.startsWith(u8, raw, "0x")) raw[2..] else raw;
    if (hex.len % 2 != 0) return error.InvalidHex;
    const bytes = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(bytes);
    for (bytes, 0..) |*byte, i| byte.* = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch return error.InvalidHex;
    return bytes;
}

/// Runs one EIP-3529 write sequence using Fulu gas and refund expectations.
fn checkSStore(allocator: std.mem.Allocator, case: SStoreCase) !void {
    const code = try hexBytes(allocator, case.code);
    defer allocator.free(code);
    var world = state.State.init(allocator);
    defer world.deinit();
    const address: state.Address = .{0x11} ** 20;
    try world.setStorage(address, 0, case.initial_slot);
    var machine = evm.Machine.init(allocator, &world);
    defer machine.deinit();
    var result = try machine.run(.{ .code = code, .gas = 100_000, .callee = address });
    defer result.deinit(allocator);
    errdefer std.log.err("SSTORE fixture failed: {s}", .{case.name});
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqual(@as(u64, 100_000 - case.gas_used), result.gas_remaining);
    try std.testing.expectEqual(case.refund, machine.refund);
    try std.testing.expectEqual(case.final_slot, world.getStorage(address, 0));
}

/// Recreates one EIP-5656 memory image and compares copy output and total gas.
fn checkMCopy(allocator: std.mem.Allocator, case: MCopyCase) !void {
    const pre = try hexBytes(allocator, case.pre);
    defer allocator.free(pre);
    const expected = try hexBytes(allocator, case.expected);
    defer allocator.free(expected);
    try std.testing.expect(pre.len == expected.len and pre.len % 32 == 0 and pre.len <= 255);
    var code: std.ArrayList(u8) = .empty;
    defer code.deinit(allocator);
    for (0..pre.len / 32) |i| {
        try code.append(allocator, 0x7f);
        try code.appendSlice(allocator, pre[i * 32 ..][0..32]);
        try code.appendSlice(allocator, &.{ 0x60, @intCast(i * 32), 0x52 });
    }
    try code.appendSlice(allocator, &.{ 0x60, case.length, 0x60, case.src, 0x60, case.dst, 0x5e, 0x60, @intCast(pre.len), 0x60, 0, 0xf3 });
    var world = state.State.init(allocator);
    defer world.deinit();
    var machine = evm.Machine.init(allocator, &world);
    defer machine.deinit();
    var result = try machine.run(.{ .code = code.items, .gas = 100_000 });
    defer result.deinit(allocator);
    errdefer std.log.err("MCOPY fixture failed: {s}", .{case.name});
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqualSlices(u8, expected, result.output);
    try std.testing.expectEqual(@as(u64, 100_000 - case.gas_used), result.gas_remaining);
}

test "pinned EVM storage and memory fixtures" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(Fixture, allocator, @embedFile("fixtures/evm_core.json"), .{});
    defer parsed.deinit();
    const fixture = parsed.value;
    try std.testing.expectEqualStrings("https://eips.ethereum.org/EIPS/eip-3529#test-cases", fixture.sstore_source);
    try std.testing.expectEqualStrings("https://eips.ethereum.org/EIPS/eip-5656#test-cases", fixture.mcopy_source);
    try std.testing.expectEqual(@as(usize, 17), fixture.sstore.len);
    try std.testing.expectEqual(@as(usize, 4), fixture.mcopy.len);
    for (fixture.sstore) |case| try checkSStore(allocator, case);
    for (fixture.mcopy) |case| try checkMCopy(allocator, case);
    std.log.info("EVM fixtures: {d} SSTORE and {d} MCOPY cases passed", .{ fixture.sstore.len, fixture.mcopy.len });
}

const PrecompileVector = struct {
    Input: []const u8,
    Expected: ?[]const u8 = null,
    ExpectedError: ?[]const u8 = null,
    Gas: ?u64 = null,
    Name: []const u8,
    NoBenchmark: ?bool = null,
};

const PrecompileSet = struct {
    name: []const u8,
    address: u8,
    fork: evm.Fork,
    bytes: []const u8,
};

// go-ethereum 6fe8b63d41be9218808adb9b25d6b21c55b37b54,
// core/vm/testdata/precompiles/*.json; the files below retain its exact bytes.
const precompile_sets = [_]PrecompileSet{
    .{ .name = "ecRecover", .address = 1, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/ecRecover.json") },
    .{ .name = "modexp_eip2565", .address = 5, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/modexp_eip2565.json") },
    .{ .name = "modexp_eip7883", .address = 5, .fork = .osaka, .bytes = @embedFile("fixtures/precompiles/modexp_eip7883.json") },
    .{ .name = "bn256Add", .address = 6, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/bn256Add.json") },
    .{ .name = "bn256ScalarMul", .address = 7, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/bn256ScalarMul.json") },
    .{ .name = "bn256Pairing", .address = 8, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/bn256Pairing.json") },
    .{ .name = "blake2F", .address = 9, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/blake2F.json") },
    .{ .name = "fail-blake2f", .address = 9, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/fail-blake2f.json") },
    .{ .name = "pointEvaluation", .address = 10, .fork = .cancun, .bytes = @embedFile("fixtures/precompiles/pointEvaluation.json") },
};

test "go-ethereum precompile vectors match output gas and failure status" {
    const allocator = std.testing.allocator;
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    for (precompile_sets) |set| {
        const parsed = try std.json.parseFromSlice([]PrecompileVector, allocator, set.bytes, .{});
        defer parsed.deinit();
        for (parsed.value) |vector| {
            errdefer std.log.err("precompile fixture {s}/{s}", .{ set.name, vector.Name });
            const input = try hexBytes(allocator, vector.Input);
            defer allocator.free(input);
            var world = state.State.init(allocator);
            defer world.deinit();
            var machine = evm.Machine.init(allocator, &world);
            defer machine.deinit();
            machine.environment = .{ .fork = set.fork, .origin = .{0} ** 20, .gas_price = 0, .coinbase = .{0} ** 20, .timestamp = 0, .number = 0, .prev_randao = 0, .gas_limit = 1_000_000, .chain_id = 1, .base_fee = 0, .blob_base_fee = 0, .kzg_settings = &settings };
            var address: state.Address = .{0} ** 20;
            address[19] = set.address;
            const gas = vector.Gas orelse 100_000;
            var result = try machine.run(.{ .code = &.{}, .gas = gas, .callee = address, .data = input });
            defer result.deinit(allocator);
            if (vector.ExpectedError != null) {
                try std.testing.expect(result.status == .fault);
                try std.testing.expectEqual(evm.Fault.invalid_opcode, result.status.fault);
                try std.testing.expectEqual(@as(u64, 0), result.gas_remaining);
                continue;
            }
            const expected = try hexBytes(allocator, vector.Expected orelse return error.MissingExpectation);
            defer allocator.free(expected);
            try std.testing.expect(result.status == .success);
            try std.testing.expectEqualSlices(u8, expected, result.output);
            try std.testing.expectEqual(@as(u64, 0), result.gas_remaining);
            if (gas > 0) {
                var short = try machine.run(.{ .code = &.{}, .gas = gas - 1, .callee = address, .data = input });
                defer short.deinit(allocator);
                try std.testing.expect(short.status == .fault);
                try std.testing.expectEqual(evm.Fault.out_of_gas, short.status.fault);
            }
        }
    }
}
