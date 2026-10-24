// These pinned EVM vectors check bytecode execution against published EIP
// examples. SSTORE rows start from a transaction-original slot value; Fulu
// adds the first cold-slot charge to EIP-3529's reduced-refund test table.
// MCOPY rows start with EIP-5656 memory images and compare the copied bytes.
// The fixture runner executes one call frame, then checks gas and state.
//
// source examples → Fulu gas expectations → interpreter → output/state
const std = @import("std");
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
    errdefer std.debug.print("SSTORE fixture failed: {s}\n", .{case.name});
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
    errdefer std.debug.print("MCOPY fixture failed: {s}\n", .{case.name});
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
    std.debug.print("EVM fixtures: {d} SSTORE and {d} MCOPY cases passed\n", .{ fixture.sstore.len, fixture.mcopy.len });
}
