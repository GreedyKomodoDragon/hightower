// EVM tests check opcode order, gas charges, and frame rollback against the
// transaction-scoped machine. A fault consumes frame gas; REVERT preserves it.
const std = @import("std");
const state = @import("../state.zig");
const core = @import("machine.zig");
const Machine = core.Machine;
const Input = core.Input;
const Fault = core.Fault;

test "PUSH ADD RETURN owns output and charges gas" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    var result = try machine.run(.{ .code = &.{ 0x60, 2, 0x60, 3, 0x01, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 }, .gas = 100 });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqual(@as(u8, 5), result.output[31]);
    try std.testing.expectEqual(@as(u64, 76), result.gas_remaining);
}

test "SHA3 hashes empty and unaligned memory with Ethereum Keccak-256" {
    const cases = [_]struct { code: []const u8, want: []const u8 }{
        .{ .code = &.{ 0x5f, 0x5f, 0x20, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 }, .want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" },
        .{ .code = &.{ 0x60, 'a', 0x5f, 0x53, 0x60, 'b', 0x60, 1, 0x53, 0x60, 'c', 0x60, 2, 0x53, 0x60, 3, 0x5f, 0x20, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 }, .want = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" },
        .{ .code = &.{ 0x60, 'a', 0x60, 1, 0x53, 0x60, 'b', 0x60, 2, 0x53, 0x60, 'c', 0x60, 3, 0x53, 0x60, 3, 0x60, 1, 0x20, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 }, .want = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" },
        .{ .code = &([_]u8{ 0x5f, 0x7f } ++ ([_]u8{0xff} ** 32) ++ [_]u8{ 0x20, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 }), .want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" },
    };
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    for (cases) |case| {
        var result = try machine.run(.{ .code = case.code, .gas = 1000 });
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result.status == .success);
        try std.testing.expectEqual(@as(usize, 32), result.output.len);
        try std.testing.expectEqualStrings(case.want, &std.fmt.bytesToHex(result.output[0..32].*, .lower));
    }
}

test "SHA3 charges base, words, and memory expansion and faults predictably" {
    const cases = [_]struct { code: []const u8, cost: u64 }{
        .{ .code = &.{ 0x5f, 0x5f, 0x20 }, .cost = 2 + 2 + 30 },
        .{ .code = &.{ 0x60, 1, 0x5f, 0x20 }, .cost = 3 + 2 + 30 + 6 + 3 },
        .{ .code = &.{ 0x60, 33, 0x5f, 0x20 }, .cost = 3 + 2 + 30 + 12 + 6 },
        .{ .code = &.{ 0x60, 2, 0x60, 31, 0x20 }, .cost = 3 + 3 + 30 + 6 + 6 },
    };
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    for (cases) |case| {
        var exact = try machine.run(.{ .code = case.code, .gas = case.cost });
        defer exact.deinit(std.testing.allocator);
        try std.testing.expect(exact.status == .success);
        try std.testing.expectEqual(@as(u64, 0), exact.gas_remaining);
        var short = try machine.run(.{ .code = case.code, .gas = case.cost - 1 });
        defer short.deinit(std.testing.allocator);
        try std.testing.expectEqual(Fault.out_of_gas, short.status.fault);
    }
    for ([_][]const u8{ &.{0x20}, &.{ 0x5f, 0x20 } }) |code| {
        var underflow = try machine.run(.{ .code = code, .gas = 100 });
        defer underflow.deinit(std.testing.allocator);
        try std.testing.expectEqual(Fault.stack_underflow, underflow.status.fault);
    }
    var overflow = try machine.run(.{ .code = &([_]u8{ 0x60, 1, 0x7f } ++ ([_]u8{0xff} ** 32) ++ [_]u8{0x20}), .gas = 100 });
    defer overflow.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.memory_overflow, overflow.status.fault);
}

/// Runs one word-producing opcode with operands in EVM top-first order.
fn testWord(op: u8, a: u256, b: u256, c: u256) !u256 {
    var code: [108]u8 = undefined;
    var pos: usize = 0;
    for ([_]u256{ c, b, a }) |value| {
        code[pos] = 0x7f;
        pos += 1;
        std.mem.writeInt(u256, code[pos..][0..32], value, .big);
        pos += 32;
    }
    const tail = [_]u8{ op, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 };
    @memcpy(code[pos..][0..tail.len], &tail);
    pos += tail.len;
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    var result = try machine.run(.{ .code = code[0..pos], .gas = 100_000 });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    return std.mem.readInt(u256, result.output[0..32], .big);
}

test "each arithmetic comparison bitwise and shift opcode" {
    const neg_two: u256 = @bitCast(@as(i256, -2));
    const min_word: u256 = @bitCast(@as(i256, std.math.minInt(i256)));
    const cases = [_]struct { op: u8, a: u256, b: u256, c: u256 = 0, want: u256 }{
        .{ .op = 0x01, .a = std.math.maxInt(u256), .b = 2, .want = 1 },
        .{ .op = 0x02, .a = 3, .b = 4, .want = 12 },
        .{ .op = 0x03, .a = 3, .b = 4, .want = std.math.maxInt(u256) },
        .{ .op = 0x04, .a = 9, .b = 2, .want = 4 },
        .{ .op = 0x05, .a = neg_two, .b = 2, .want = @bitCast(@as(i256, -1)) },
        .{ .op = 0x06, .a = 9, .b = 4, .want = 1 },
        .{ .op = 0x07, .a = neg_two, .b = 3, .want = neg_two },
        .{ .op = 0x08, .a = std.math.maxInt(u256), .b = 2, .c = 7, .want = 3 },
        .{ .op = 0x09, .a = 10, .b = 10, .c = 7, .want = 2 },
        .{ .op = 0x0a, .a = 2, .b = 8, .want = 256 },
        .{ .op = 0x0b, .a = 0, .b = 0x80, .want = std.math.maxInt(u256) - 0x7f },
        .{ .op = 0x10, .a = 1, .b = 2, .want = 1 },
        .{ .op = 0x11, .a = 3, .b = 2, .want = 1 },
        .{ .op = 0x12, .a = neg_two, .b = 1, .want = 1 },
        .{ .op = 0x13, .a = 1, .b = neg_two, .want = 1 },
        .{ .op = 0x14, .a = 7, .b = 7, .want = 1 },
        .{ .op = 0x15, .a = 0, .b = 8, .want = 1 },
        .{ .op = 0x16, .a = 0b1100, .b = 0b1010, .want = 0b1000 },
        .{ .op = 0x17, .a = 0b1100, .b = 0b1010, .want = 0b1110 },
        .{ .op = 0x18, .a = 0b1100, .b = 0b1010, .want = 0b0110 },
        .{ .op = 0x19, .a = 0, .b = 1, .want = std.math.maxInt(u256) },
        .{ .op = 0x1a, .a = 31, .b = 0xff, .want = 0xff },
        .{ .op = 0x1b, .a = 8, .b = 1, .want = 256 },
        .{ .op = 0x1c, .a = 8, .b = 256, .want = 1 },
        .{ .op = 0x1d, .a = 1, .b = neg_two, .want = @bitCast(@as(i256, -1)) },
    };
    for (cases) |case| try std.testing.expectEqual(case.want, try testWord(case.op, case.a, case.b, case.c));
    try std.testing.expectEqual(@as(u256, 0), try testWord(0x04, 9, 0, 0));
    try std.testing.expectEqual(min_word, try testWord(0x05, min_word, std.math.maxInt(u256), 0));
    try std.testing.expectEqual(@as(u256, 0), try testWord(0x07, min_word, std.math.maxInt(u256), 0));
    try std.testing.expectEqual(@as(u256, 0), try testWord(0x1b, 256, 1, 0));
}

test "stack, memory, jump, and deterministic faults" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const Case = struct { code: []const u8, fault: Fault };
    const cases = [_]Case{
        .{ .code = &.{0x01}, .fault = .stack_underflow },
        .{ .code = &.{0xfe}, .fault = .invalid_opcode },
        .{ .code = &.{ 0x60, 1, 0x56, 0x5b }, .fault = .invalid_jump },
        .{ .code = &.{ 0x60, 4, 0x60, 1, 0x57, 0x00 }, .fault = .invalid_jump },
        .{ .code = &.{ 0x60, 1, 0x56 }, .fault = .invalid_jump },
        .{ .code = &.{ 0x60, 1, 0x00 }, .fault = .out_of_gas },
    };
    for (cases, 0..) |case, i| {
        var result = try machine.run(.{ .code = case.code, .gas = if (i == cases.len - 1) 2 else 100 });
        defer result.deinit(std.testing.allocator);
        try std.testing.expectEqual(case.fault, result.status.fault);
        try std.testing.expectEqual(@as(u64, 0), result.gas_remaining);
    }
    var depth = try machine.run(.{ .code = &.{0x00}, .gas = 100, .depth = 1024 });
    defer depth.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.depth, depth.status.fault);
    const pushes = try std.testing.allocator.alloc(u8, 1025);
    defer std.testing.allocator.free(pushes);
    @memset(pushes, 0x5f);
    var overflow = try machine.run(.{ .code = pushes, .gas = 3000 });
    defer overflow.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.stack_overflow, overflow.status.fault);
    var huge = try machine.run(.{ .code = &([_]u8{0x7f} ++ ([_]u8{0xff} ** 32) ++ [_]u8{0x51}), .gas = 100_000 });
    defer huge.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.memory_overflow, huge.status.fault);
}

test "memory copy handles overlap and revert returns bytes with gas" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    // Store abc, copy [0..3] to [1..4], and return the four-byte result.
    const code = [_]u8{ 0x60, 'a', 0x60, 0, 0x53, 0x60, 'b', 0x60, 1, 0x53, 0x60, 'c', 0x60, 2, 0x53, 0x60, 3, 0x60, 0, 0x60, 1, 0x5e, 0x60, 4, 0x60, 0, 0xfd };
    var result = try machine.run(.{ .code = &code, .gas = 100 });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .revert);
    try std.testing.expectEqualStrings("aabc", result.output);
    try std.testing.expectEqual(@as(u64, 49), result.gas_remaining);
}

test "SLOAD and SSTORE meter cold warm original and dirty slots" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const address: state.Address = .{1} ** 20;
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const initial_root = try world.stateRoot();
    // 22100 cold set, 100 warm load, 100 dirty write, 100 warm load.
    const code = [_]u8{ 0x60, 7, 0x60, 1, 0x55, 0x60, 1, 0x54, 0x50, 0x60, 8, 0x60, 1, 0x55, 0x60, 1, 0x54, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 };
    var result = try machine.run(.{ .code = &code, .gas = 30_000, .callee = address });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqual(@as(u8, 8), result.output[31]);
    try std.testing.expectEqual(@as(u256, 8), world.getStorage(address, 1));
    try std.testing.expect(!std.mem.eql(u8, &initial_root, &(try world.stateRoot())));
    try std.testing.expectEqual(@as(u64, 7565), result.gas_remaining);
    // The transaction-original value remains zero across successful frames.
    try std.testing.expectEqual(@as(u256, 0), machine.original.items[0].value);
    try std.testing.expectEqual(@as(i128, 0), machine.refund);
}

test "reverted SSTORE and TSTORE restore state root and transient value" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const address: state.Address = .{2} ** 20;
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const root = try world.stateRoot();
    const commit_code = [_]u8{ 0x60, 4, 0x60, 9, 0x5d, 0x00 };
    var committed = try machine.run(.{ .code = &commit_code, .gas = 1000, .callee = address });
    defer committed.deinit(std.testing.allocator);
    try std.testing.expect(committed.status == .success);
    const revert_code = [_]u8{ 0x60, 3, 0x60, 1, 0x55, 0x60, 5, 0x60, 9, 0x5d, 0x60, 0, 0x60, 0, 0xfd };
    var reverted = try machine.run(.{ .code = &revert_code, .gas = 30_000, .callee = address });
    defer reverted.deinit(std.testing.allocator);
    try std.testing.expect(reverted.status == .revert);
    try std.testing.expectEqual(@as(u64, 7782), reverted.gas_remaining);
    try std.testing.expectEqual(@as(u256, 0), world.getStorage(address, 1));
    try std.testing.expectEqualSlices(u8, &root, &(try world.stateRoot()));
    const load_code = [_]u8{ 0x60, 9, 0x5c, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 };
    var loaded = try machine.run(.{ .code = &load_code, .gas = 1000, .callee = address });
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 4), loaded.output[31]);
    var other = try machine.run(.{ .code = &load_code, .gas = 1000, .callee = .{3} ** 20 });
    defer other.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), other.output[31]);
    var static = try machine.run(.{ .code = &commit_code, .gas = 1000, .callee = address, .is_static = true });
    defer static.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.write_protection, static.status.fault);
}

test "control stack and memory opcodes" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    // PUSH0, DUP1, SWAP1, POP, PC, JUMPI, JUMPDEST, MSTORE8, MLOAD, MSIZE, GAS.
    const code = [_]u8{ 0x5f, 0x60, 1, 0x80, 0x90, 0x50, 0x50, 0x60, 1, 0x60, 13, 0x57, 0xfe, 0x5b, 0x58, 0x60, 0, 0x53, 0x60, 0, 0x51, 0x50, 0x59, 0x50, 0x5a, 0x50, 0x00 };
    var result = try machine.run(.{ .code = &code, .gas = 1000 });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expect(result.gas_remaining < 1000);
}

test "all PUSH DUP and SWAP widths" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    for (1..33) |width| {
        var code: [44]u8 = undefined;
        code[0] = @intCast(0x5f + width);
        @memset(code[1 .. width + 1], 0);
        code[width] = 42;
        const tail = [_]u8{ 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 };
        @memcpy(code[width + 1 ..][0..tail.len], &tail);
        var result = try machine.run(.{ .code = code[0 .. width + 1 + tail.len], .gas = 100 });
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result.status == .success);
        try std.testing.expectEqual(@as(u8, 42), result.output[31]);
    }
    for (1..17) |depth| {
        var code: [64]u8 = undefined;
        var pos: usize = 0;
        for (1..depth + 2) |value| {
            code[pos] = 0x60;
            code[pos + 1] = @intCast(value);
            pos += 2;
        }
        code[pos] = @intCast(0x7f + depth);
        pos += 1;
        const tail = [_]u8{ 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 };
        @memcpy(code[pos..][0..tail.len], &tail);
        var dup = try machine.run(.{ .code = code[0 .. pos + tail.len], .gas = 200 });
        defer dup.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 2), dup.output[31]);
        code[pos - 1] = @intCast(0x8f + depth);
        var swap = try machine.run(.{ .code = code[0 .. pos + tail.len], .gas = 200 });
        defer swap.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 1), swap.output[31]);
    }
}

test "JUMP accepts only JUMPDEST outside push data" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    var result = try machine.run(.{ .code = &.{ 0x60, 4, 0x56, 0xfe, 0x5b, 0x00 }, .gas = 20 });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqual(@as(u64, 8), result.gas_remaining);
}

test "memory expansion charges words and quadratic term" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    // MSTORE at 32,768 expands through word 1,025: 3*w + floor(w*w/512).
    const code = [_]u8{ 0x5f, 0x61, 0x80, 0x00, 0x52, 0x00 };
    var result = try machine.run(.{ .code = &code, .gas = 6000 });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    const words: u64 = 1025;
    try std.testing.expectEqual(@as(u64, 6000 - (2 + 3 + 3 + 3 * words + words * words / 512)), result.gas_remaining);
}

test "failed frame undoes prior SSTORE and warming" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const address: state.Address = .{4} ** 20;
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const code = [_]u8{ 0x60, 1, 0x60, 2, 0x55, 0xfe };
    var result = try machine.run(.{ .code = &code, .gas = 30_000, .callee = address });
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.invalid_opcode, result.status.fault);
    try std.testing.expectEqual(@as(u256, 0), world.getStorage(address, 2));
    try std.testing.expectEqual(@as(usize, 0), machine.warm.items.len);
    try std.testing.expectEqual(@as(u256, 0), machine.original.items[0].value);
}

test "nonzero original SSTORE reset costs and refund" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const address: state.Address = .{5} ** 20;
    try world.setStorage(address, 1, 9);
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    // First clear: 2100 cold + 2900 reset. Dirty restoration: 100 warm.
    const code = [_]u8{ 0x5f, 0x60, 1, 0x55, 0x60, 9, 0x60, 1, 0x55, 0x00 };
    var result = try machine.run(.{ .code = &code, .gas = 10_000, .callee = address });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqual(@as(u256, 9), world.getStorage(address, 1));
    try std.testing.expectEqual(@as(i128, 2800), machine.refund);
    try std.testing.expectEqual(@as(u64, 4889), result.gas_remaining);
}

test "PC MSIZE GAS MLOAD and STOP return expected values" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const cases = [_]struct { code: []const u8, expected: u8, index: usize = 31 }{
        .{ .code = &.{ 0x5f, 0x58, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 }, .expected = 1 },
        .{ .code = &.{ 0x60, 7, 0x60, 0, 0x53, 0x59, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 }, .expected = 32 },
        .{ .code = &.{ 0x5a, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 }, .expected = 98 },
        .{ .code = &.{ 0x60, 42, 0x60, 0, 0x53, 0x60, 0, 0x51, 0x60, 32, 0x52, 0x60, 32, 0x60, 32, 0xf3 }, .expected = 42, .index = 0 },
    };
    for (cases) |case| {
        var result = try machine.run(.{ .code = case.code, .gas = 100 });
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result.status == .success);
        try std.testing.expectEqual(case.expected, result.output[case.index]);
    }
    var stopped = try machine.run(.{ .code = &.{ 0x60, 2, 0x60, 3, 0x01, 0x00 }, .gas = 20, .depth = 1023 });
    defer stopped.deinit(std.testing.allocator);
    try std.testing.expect(stopped.status == .success);
    try std.testing.expectEqual(@as(u64, 11), stopped.gas_remaining);
}

test "MCOPY copies overlapping memory toward lower addresses" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const code = [_]u8{ 0x60, 'a', 0x60, 0, 0x53, 0x60, 'b', 0x60, 1, 0x53, 0x60, 'c', 0x60, 2, 0x53, 0x60, 'd', 0x60, 3, 0x53, 0x60, 3, 0x60, 1, 0x60, 0, 0x5e, 0x60, 4, 0x60, 0, 0xf3 };
    var result = try machine.run(.{ .code = &code, .gas = 100 });
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("bcdd", result.output);
}

test "SSTORE stipend guard and TSTORE below stipend" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    var sstore_result = try machine.run(.{ .code = &.{ 0x5f, 0x5f, 0x55 }, .gas = 2304 });
    defer sstore_result.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.out_of_gas, sstore_result.status.fault);
    var tstore_result = try machine.run(.{ .code = &.{ 0x5f, 0x5f, 0x5d }, .gas = 104 });
    defer tstore_result.deinit(std.testing.allocator);
    try std.testing.expect(tstore_result.status == .success);
    try std.testing.expectEqual(@as(u64, 0), tstore_result.gas_remaining);
}

test "cold and warm SLOAD and no-op SSTORE charges" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const address: state.Address = .{6} ** 20;
    try world.setStorage(address, 1, 9);
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const code = [_]u8{ 0x60, 1, 0x54, 0x50, 0x60, 1, 0x54, 0x50, 0x60, 9, 0x60, 1, 0x55, 0x00 };
    var result = try machine.run(.{ .code = &code, .gas = 10_000, .callee = address });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqual(@as(u64, 7684), result.gas_remaining);
    try std.testing.expectEqual(@as(u256, 9), world.getStorage(address, 1));
    try std.testing.expectEqual(@as(i128, 0), machine.refund);
}

/// Runs one opcode and returns its top stack word as 32 big-endian bytes.
fn opcodeWord(machine: *Machine, op: u8, operand: ?u8, input: Input) !u256 {
    var code: [10]u8 = undefined;
    var n: usize = 0;
    if (operand) |value| {
        code[n] = 0x60;
        code[n + 1] = value;
        n += 2;
    }
    const tail = [_]u8{ op, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 };
    @memcpy(code[n..][0..tail.len], &tail);
    n += tail.len;
    var frame_input = input;
    frame_input.code = code[0..n];
    var result = try machine.run(frame_input);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    return std.mem.readInt(u256, result.output[0..32], .big);
}

test "environment opcodes use supplied context and reject missing context" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const caller: state.Address = .{0} ** 19 ++ .{7};
    const callee: state.Address = .{0} ** 19 ++ .{8};
    const input = Input{ .code = &.{}, .gas = 100_000, .caller = caller, .callee = callee, .value = 11, .data = "abc" };
    var absent = try machine.run(.{ .code = &.{0x32}, .gas = 100 });
    defer absent.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.missing_context, absent.status.fault);
    const hashes = [_]state.Hash{.{0} ** 31 ++ .{0xaa}};
    const blobs = [_]state.Hash{.{0} ** 31 ++ .{0xbb}};
    machine.environment = .{ .origin = caller, .gas_price = 12, .coinbase = callee, .timestamp = 13, .number = 50, .prev_randao = 14, .gas_limit = 15, .chain_id = 16, .base_fee = 17, .blob_base_fee = 18, .block_hashes = &hashes, .blob_hashes = &blobs };
    const cases = [_]struct { op: u8, operand: ?u8 = null, want: u256 }{
        .{ .op = 0x30, .want = 8 },
        .{ .op = 0x32, .want = 7 },
        .{ .op = 0x33, .want = 7 },
        .{ .op = 0x34, .want = 11 },
        .{ .op = 0x35, .operand = 1, .want = @as(u256, 'b') << 248 | @as(u256, 'c') << 240 },
        .{ .op = 0x36, .want = 3 },
        .{ .op = 0x38, .want = 7 },
        .{ .op = 0x3a, .want = 12 },
        .{ .op = 0x40, .operand = 49, .want = 0xaa },
        .{ .op = 0x40, .operand = 50, .want = 0 },
        .{ .op = 0x40, .operand = 51, .want = 0 },
        .{ .op = 0x41, .want = 8 },
        .{ .op = 0x42, .want = 13 },
        .{ .op = 0x43, .want = 50 },
        .{ .op = 0x44, .want = 14 },
        .{ .op = 0x45, .want = 15 },
        .{ .op = 0x46, .want = 16 },
        .{ .op = 0x47, .want = 0 },
        .{ .op = 0x48, .want = 17 },
        .{ .op = 0x49, .operand = 0, .want = 0xbb },
        .{ .op = 0x49, .operand = 1, .want = 0 },
        .{ .op = 0x4a, .want = 18 },
    };
    for (cases) |case| try std.testing.expectEqual(case.want, try opcodeWord(&machine, case.op, case.operand, input));
    var unavailable = try machine.run(.{ .code = &.{ 0x60, 48, 0x40 }, .gas = 100 });
    defer unavailable.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.missing_context, unavailable.status.fault);
}

test "BLOCKHASH includes the 256th parent and excludes older blocks" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    var hashes: [256]state.Hash = .{.{0} ** 32} ** 256;
    hashes[255][31] = 0xee;
    machine.environment = .{ .origin = .{0} ** 20, .gas_price = 0, .coinbase = .{0} ** 20, .timestamp = 0, .number = 300, .prev_randao = 0, .gas_limit = 0, .chain_id = 1, .base_fee = 0, .blob_base_fee = 0, .block_hashes = &hashes };
    const input = Input{ .code = &.{}, .gas = 100 };
    try std.testing.expectEqual(@as(u256, 0xee), try opcodeWord(&machine, 0x40, 44, input));
    try std.testing.expectEqual(@as(u256, 0), try opcodeWord(&machine, 0x40, 43, input));
}

test "access list warms accounts and slots; refunds cap at one fifth" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const address: state.Address = .{0} ** 19 ++ .{0x20};
    try world.setBalance(address, 3);
    try world.setStorage(address, 1, 9);
    var cold = Machine.init(std.testing.allocator, &world);
    defer cold.deinit();
    var cold_balance = try cold.run(.{ .code = &.{ 0x60, 0x20, 0x31 }, .gas = 3000 });
    defer cold_balance.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 397), cold_balance.gas_remaining);
    var warm_balance = try cold.run(.{ .code = &.{ 0x60, 0x20, 0x31 }, .gas = 3000 });
    defer warm_balance.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 2897), warm_balance.gas_remaining);
    var listed = Machine.init(std.testing.allocator, &world);
    defer listed.deinit();
    try listed.configure(.{ .origin = address, .gas_price = 0, .coinbase = .{0} ** 20, .timestamp = 0, .number = 0, .prev_randao = 0, .gas_limit = 0, .chain_id = 1, .base_fee = 0, .blob_base_fee = 0 }, .{0} ** 20, .{0} ** 20, &.{.{ .address = address, .storage_keys = &.{1} }});
    var listed_balance = try listed.run(.{ .code = &.{ 0x60, 0x20, 0x31 }, .gas = 3000 });
    defer listed_balance.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 2897), listed_balance.gas_remaining);
    var load = try listed.run(.{ .code = &.{ 0x60, 1, 0x54 }, .gas = 3000, .callee = address });
    defer load.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 2897), load.gas_remaining);
    listed.refund = 4800;
    try std.testing.expectEqual(@as(u64, 100), listed.cappedRefund(500));
    try std.testing.expectEqual(@as(u64, 4800), listed.cappedRefund(30_000));
    try std.testing.expectEqual(@as(i128, 0), Machine.init(std.testing.allocator, &world).refund);
}

test "LOG topics and data commit in order and revert with their frame" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const address: state.Address = .{0} ** 19 ++ .{0x20};
    const prefix = [_]u8{ 0x60, 'x', 0x5f, 0x53, 0x60, 0x11, 0x60, 1, 0x5f, 0xa1 };
    var committed = try machine.run(.{ .code = &prefix, .gas = 2000, .callee = address });
    defer committed.deinit(std.testing.allocator);
    try std.testing.expect(committed.status == .success);
    try std.testing.expectEqual(@as(usize, 1), machine.emittedLogs().len);
    try std.testing.expectEqualSlices(u8, "x", machine.emittedLogs()[0].data);
    try std.testing.expectEqual(@as(u8, 1), machine.emittedLogs()[0].topic_count);
    try std.testing.expectEqual(@as(u8, 0x11), machine.emittedLogs()[0].topics[0][31]);
    try std.testing.expectEqualSlices(u8, &address, &machine.emittedLogs()[0].address);
    const reverting = prefix ++ [_]u8{ 0x5f, 0x5f, 0xfd };
    var reverted = try machine.run(.{ .code = &reverting, .gas = 2000, .callee = address });
    defer reverted.deinit(std.testing.allocator);
    try std.testing.expect(reverted.status == .revert);
    try std.testing.expectEqual(@as(usize, 1), machine.emittedLogs().len);
    var denied = try machine.run(.{ .code = &prefix, .gas = 2000, .callee = address, .is_static = true });
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.write_protection, denied.status.fault);
    try std.testing.expectEqual(@as(usize, 1), machine.emittedLogs().len);
}

test "CALL transfers value, returns data, and child REVERT restores value and logs" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const parent: state.Address = .{0} ** 19 ++ .{0x20};
    const child: state.Address = .{0} ** 19 ++ .{0x21};
    try world.setBalance(parent, 100);
    _ = try world.setCode(child, &.{ 0x60, 0xab, 0x5f, 0x53, 0x60, 1, 0x5f, 0xf3 });
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const code = [_]u8{ 0x60, 1, 0x5f, 0x5f, 0x5f, 0x60, 7, 0x60, 0x21, 0x61, 0xff, 0xff, 0xf1, 0x50, 0x60, 1, 0x5f, 0xf3 };
    var result = try machine.run(.{ .code = &code, .gas = 100_000, .callee = parent });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqualSlices(u8, &.{0xab}, result.output);
    try std.testing.expectEqual(@as(u256, 93), world.getBalance(parent));
    try std.testing.expectEqual(@as(u256, 7), world.getBalance(child));

    _ = try world.setCode(child, &.{ 0x60, 'z', 0x5f, 0x53, 0x60, 1, 0x5f, 0xa0, 0x5f, 0x5f, 0xfd });
    var failed = try machine.run(.{ .code = &code, .gas = 100_000, .callee = parent });
    defer failed.deinit(std.testing.allocator);
    try std.testing.expect(failed.status == .success);
    try std.testing.expectEqual(@as(u256, 93), world.getBalance(parent));
    try std.testing.expectEqual(@as(u256, 7), world.getBalance(child));
    try std.testing.expectEqual(@as(usize, 0), machine.emittedLogs().len);
}

test "CALL family preserves caller, value, address, static mode, and depth failure" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const parent: state.Address = .{0} ** 19 ++ .{0x20};
    const child: state.Address = .{0} ** 19 ++ .{0x21};
    const origin: state.Address = .{0} ** 19 ++ .{0x22};
    try world.setBalance(parent, 100);
    // Child returns ADDRESS, CALLER, and CALLVALUE as consecutive words.
    _ = try world.setCode(child, &.{ 0x30, 0x5f, 0x52, 0x33, 0x60, 32, 0x52, 0x34, 0x60, 64, 0x52, 0x60, 96, 0x5f, 0xf3 });
    const call_prefix = [_]u8{ 0x60, 96, 0x5f, 0x5f, 0x5f, 0x60, 7, 0x60, 0x21, 0x61, 0xff, 0xff };
    const no_value_prefix = [_]u8{ 0x60, 96, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x61, 0xff, 0xff };
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const cases = [_]struct { op: u8, address: u256, caller: u256, value: u256 }{
        .{ .op = 0xf1, .address = 0x21, .caller = 0x20, .value = 7 },
        .{ .op = 0xf2, .address = 0x20, .caller = 0x20, .value = 7 },
        .{ .op = 0xf4, .address = 0x20, .caller = 0x22, .value = 5 },
        .{ .op = 0xfa, .address = 0x21, .caller = 0x20, .value = 0 },
    };
    for (cases) |case| {
        var code: [18]u8 = undefined;
        const prefix: []const u8 = if (case.op == 0xf1 or case.op == 0xf2) &call_prefix else &no_value_prefix;
        @memcpy(code[0..prefix.len], prefix);
        const tail = [_]u8{ case.op, 0x50, 0x60, 96, 0x5f, 0xf3 };
        @memcpy(code[prefix.len..][0..tail.len], &tail);
        var result = try machine.run(.{ .code = code[0 .. prefix.len + tail.len], .gas = 100_000, .caller = origin, .callee = parent, .value = 5 });
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result.status == .success);
        try std.testing.expectEqual(case.address, std.mem.readInt(u256, result.output[0..32], .big));
        try std.testing.expectEqual(case.caller, std.mem.readInt(u256, result.output[32..64], .big));
        try std.testing.expectEqual(case.value, std.mem.readInt(u256, result.output[64..96], .big));
    }
    const depth_code = call_prefix ++ [_]u8{ 0xf1, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 };
    var depth = try machine.run(.{ .code = &depth_code, .gas = 100_000, .callee = parent, .depth = 1023 });
    defer depth.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u256, 0), std.mem.readInt(u256, depth.output[0..32], .big));
}

test "copy and external-code opcodes pad reads and enforce return-data bounds" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const child: state.Address = .{0} ** 19 ++ .{0x21};
    const code_hash = try world.setCode(child, &.{ 0x60, 'a', 0x5f, 0x53, 0x60, 'b', 0x60, 1, 0x53, 0x60, 'c', 0x60, 2, 0x53, 0x60, 3, 0x5f, 0xf3 });
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    try std.testing.expectEqual(@as(u256, 18), try opcodeWord(&machine, 0x3b, 0x21, .{ .code = &.{}, .gas = 20_000 }));
    try std.testing.expectEqual(std.mem.readInt(u256, &code_hash, .big), try opcodeWord(&machine, 0x3f, 0x21, .{ .code = &.{}, .gas = 20_000 }));
    try std.testing.expectEqual(@as(u256, 0), try opcodeWord(&machine, 0x3f, 0x22, .{ .code = &.{}, .gas = 20_000 }));
    const data_copy = [_]u8{ 0x60, 4, 0x5f, 0x5f, 0x37, 0x60, 4, 0x5f, 0xf3 };
    var data = try machine.run(.{ .code = &data_copy, .gas = 100, .data = "ab" });
    defer data.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 'a', 'b', 0, 0 }, data.output);
    const ext_copy = [_]u8{ 0x60, 3, 0x60, 16, 0x5f, 0x60, 0x21, 0x3c, 0x60, 3, 0x5f, 0xf3 };
    var ext = try machine.run(.{ .code = &ext_copy, .gas = 20_000 });
    defer ext.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0x5f, 0xf3, 0 }, ext.output);
    const code_copy = [_]u8{ 0x60, 3, 0x60, 8, 0x5f, 0x39, 0x60, 3, 0x5f, 0xf3 };
    var copied = try machine.run(.{ .code = &code_copy, .gas = 100 });
    defer copied.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0x5f, 0xf3, 0 }, copied.output);
    const return_copy = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x61, 0x27, 0x10, 0xfa, 0x50, 0x3d, 0x50, 0x60, 2, 0x60, 1, 0x5f, 0x3e, 0x60, 2, 0x5f, 0xf3 };
    var returned = try machine.run(.{ .code = &return_copy, .gas = 30_000 });
    defer returned.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("bc", returned.output);
    const return_size = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x61, 0x27, 0x10, 0xfa, 0x50, 0x3d, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 };
    var size = try machine.run(.{ .code = &return_size, .gas = 30_000 });
    defer size.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u256, 3), std.mem.readInt(u256, size.output[0..32], .big));
    const out_of_bounds = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x61, 0x27, 0x10, 0xfa, 0x50, 0x60, 3, 0x60, 1, 0x5f, 0x3e };
    var invalid = try machine.run(.{ .code = &out_of_bounds, .gas = 30_000 });
    defer invalid.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.invalid_opcode, invalid.status.fault);
}

test "EIP-150 caps forwarded gas and precompile calls fail explicitly" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const child: state.Address = .{0} ** 19 ++ .{0x21};
    _ = try world.setCode(child, &.{ 0x5a, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 });
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const code = [_]u8{ 0x60, 32, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x62, 0xff, 0xff, 0xff, 0xfa, 0x50, 0x60, 32, 0x5f, 0xf3 };
    var result = try machine.run(.{ .code = &code, .gas = 100_000 });
    defer result.deinit(std.testing.allocator);
    const available: u64 = 100_000 - 15 - 3 - 2600;
    try std.testing.expectEqual(@as(u256, available - available / 64 - 2), std.mem.readInt(u256, result.output[0..32], .big));
    const precompile = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 1, 0x60, 1, 0xfa };
    var unsupported = try machine.run(.{ .code = &precompile, .gas = 10_000 });
    defer unsupported.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.unsupported_precompile, unsupported.status.fault);
    const bls_precompile = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x11, 0x60, 1, 0xfa };
    var bls = try machine.run(.{ .code = &bls_precompile, .gas = 10_000 });
    defer bls.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.unsupported_precompile, bls.status.fault);
}

test "value CALL supplies the 2300 gas stipend when requested gas is zero" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const parent: state.Address = .{0} ** 19 ++ .{0x20};
    const child: state.Address = .{0} ** 19 ++ .{0x21};
    try world.setBalance(parent, 1);
    _ = try world.setCode(child, &.{ 0x5a, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 });
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const code = [_]u8{ 0x60, 32, 0x5f, 0x5f, 0x5f, 0x60, 1, 0x60, 0x21, 0x5f, 0xf1, 0x50, 0x60, 32, 0x5f, 0xf3 };
    var result = try machine.run(.{ .code = &code, .gas = 50_000, .callee = parent });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.status == .success);
    try std.testing.expectEqual(@as(u256, 2298), std.mem.readInt(u256, result.output[0..32], .big));
    try std.testing.expectEqual(@as(u256, 1), world.getBalance(child));
}

test "LOG0 through LOG4 retain topic order" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    for (0..5) |count| {
        var code: [16]u8 = undefined;
        var n: usize = 0;
        var topic = count;
        while (topic > 0) : (topic -= 1) {
            code[n] = 0x60;
            code[n + 1] = @intCast(topic);
            n += 2;
        }
        code[n] = 0x5f;
        code[n + 1] = 0x5f;
        code[n + 2] = @intCast(0xa0 + count);
        var result = try machine.run(.{ .code = code[0 .. n + 3], .gas = 3000 });
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result.status == .success);
        const log_entry = machine.emittedLogs()[count];
        try std.testing.expectEqual(@as(u8, @intCast(count)), log_entry.topic_count);
        for (0..count) |i| try std.testing.expectEqual(@as(u8, @intCast(i + 1)), log_entry.topics[i][31]);
    }
}

test "LOG data cost overflow faults instead of trapping" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const length = [_]u8{ 0x67, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const log0 = length ++ [_]u8{ 0x5f, 0xa0 };
    var zero_topics = try machine.run(.{ .code = &log0, .gas = 100_000 });
    defer zero_topics.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.out_of_gas, zero_topics.status.fault);
    const log4 = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f } ++ length ++ [_]u8{ 0x5f, 0xa4 };
    var four_topics = try machine.run(.{ .code = &log4, .gas = 100_000 });
    defer four_topics.deinit(std.testing.allocator);
    try std.testing.expectEqual(Fault.out_of_gas, four_topics.status.fault);
}

test "value CALL charges new-account gas for absent and explicit empty recipients" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const parent: state.Address = .{0} ** 19 ++ .{0x20};
    const empty: state.Address = .{0} ** 19 ++ .{0x22};
    const nonempty: state.Address = .{0} ** 19 ++ .{0x23};
    try world.createAccount(empty);
    try world.setNonce(nonempty, 1);
    var gas_remaining: [3]u64 = undefined;
    for ([_]u8{ 0x21, 0x22, 0x23 }, 0..) |recipient, i| {
        try world.setBalance(parent, 10);
        var machine = Machine.init(std.testing.allocator, &world);
        defer machine.deinit();
        const code = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 1, 0x60, recipient, 0x5f, 0xf1 };
        var result = try machine.run(.{ .code = &code, .gas = 100_000, .callee = parent });
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result.status == .success);
        gas_remaining[i] = result.gas_remaining;
    }
    try std.testing.expectEqual(gas_remaining[0], gas_remaining[1]);
    try std.testing.expectEqual(gas_remaining[0] + 25_000, gas_remaining[2]);
}

test "child storage and transient writes revert; STATICCALL cannot write" {
    var world = state.State.init(std.testing.allocator);
    defer world.deinit();
    const child: state.Address = .{0} ** 19 ++ .{0x21};
    _ = try world.setCode(child, &.{ 0x60, 9, 0x60, 1, 0x55, 0x60, 7, 0x60, 2, 0x5d, 0x5f, 0x5f, 0xfd });
    var machine = Machine.init(std.testing.allocator, &world);
    defer machine.deinit();
    const code = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x61, 0x27, 0x10, 0xfa, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3 };
    var denied = try machine.run(.{ .code = &code, .gas = 30_000 });
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u256, 0), std.mem.readInt(u256, denied.output[0..32], .big));
    try std.testing.expectEqual(@as(u256, 0), world.getStorage(child, 1));
    const call_code = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x61, 0xff, 0xff, 0xf1 };
    var reverted = try machine.run(.{ .code = &call_code, .gas = 100_000 });
    defer reverted.deinit(std.testing.allocator);
    try std.testing.expect(reverted.status == .success);
    try std.testing.expectEqual(@as(u256, 0), world.getStorage(child, 1));
    try std.testing.expectEqual(@as(usize, 0), machine.transient.items.len);
}
