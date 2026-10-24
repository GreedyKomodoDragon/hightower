// The EVM executes one call frame in opcode order. Its 256-bit stack supplies
// operands, memory expands in 32-byte words and is billed before access, and
// persistent storage is billed against its transaction-original value.
// A frame snapshot commits on STOP/RETURN and rolls back on REVERT or fault;
// transient storage, logs, and warm accesses follow the same frame boundary. This core
// accepts at most 1,024 stack words and frame depths 0..1,023.
//
// code → stack/memory → storage snapshot → commit or rollback
// shortcut: transaction-local keys scan arrays and frame checkpoints copy them; use indexed journals if profiling shows this is costly.
const std = @import("std");
const state = @import("state.zig");

/// Host values shared by every frame of one transaction. Block hashes are newest first.
pub const Environment = struct {
    origin: state.Address,
    gas_price: u256,
    coinbase: state.Address,
    timestamp: u64,
    number: u64,
    prev_randao: u256,
    gas_limit: u64,
    chain_id: u256,
    base_fee: u256,
    blob_base_fee: u256,
    blob_hashes: []const state.Hash = &.{},
    block_hashes: ?[]const state.Hash = null,
};

/// Access-list entry borrowed by the machine for transaction prewarming.
pub const Access = struct { address: state.Address, storage_keys: []const u256 = &.{} };

/// An emitted log owns its data; the machine owns logs until deinit.
pub const Log = struct { address: state.Address, topics: [4]state.Hash, topic_count: u8, data: []const u8 };

pub const Input = struct {
    code: []const u8,
    gas: u64,
    caller: state.Address = .{0} ** 20,
    callee: state.Address = .{0} ** 20,
    value: u256 = 0,
    data: []const u8 = &.{},
    depth: u16 = 0,
    is_static: bool = false,
};
pub const Fault = enum { out_of_gas, stack_underflow, stack_overflow, invalid_opcode, invalid_jump, depth, write_protection, memory_overflow, missing_context, unsupported_precompile };
pub const Status = union(enum) { success, revert, fault: Fault };
pub const Result = struct {
    status: Status,
    gas_remaining: u64,
    output: []u8,
    /// Releases the result's owned return bytes.
    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        allocator.free(self.output);
    }
};
const Slot = struct { address: state.Address, key: u256, value: u256 };
const Key = struct { address: state.Address, key: u256 };
const Original = struct { address: state.Address, key: u256, value: u256 };

/// Transaction-scoped EVM context; discard it after the transaction ends.
pub const Machine = struct {
    allocator: std.mem.Allocator,
    world: *state.State,
    transient: std.ArrayList(Slot) = .empty,
    warm: std.ArrayList(Key) = .empty,
    warm_accounts: std.ArrayList(state.Address) = .empty,
    original: std.ArrayList(Original) = .empty,
    logs: std.ArrayList(Log) = .empty,
    environment: ?Environment = null,
    refund: i128 = 0,

    /// Borrows execution state and retains transaction-local data until deinit.
    pub fn init(allocator: std.mem.Allocator, world: *state.State) Machine {
        return .{ .allocator = allocator, .world = world };
    }
    /// Sets the transaction context and prewarms transaction participants and access-list entries.
    pub fn configure(self: *Machine, environment: Environment, sender: state.Address, recipient: state.Address, access_list: []const Access) !void {
        self.environment = environment;
        _ = try self.touchAccount(sender);
        _ = try self.touchAccount(recipient);
        _ = try self.touchAccount(environment.coinbase);
        for (1..18) |i| {
            var address: state.Address = .{0} ** 20;
            address[19] = @intCast(i);
            _ = try self.touchAccount(address);
        }
        for (access_list) |access| {
            _ = try self.touchAccount(access.address);
            for (access.storage_keys) |key| _ = try self.touch(access.address, key);
        }
    }
    /// Borrows committed transaction logs until the next run or deinit.
    pub fn emittedLogs(self: *const Machine) []const Log {
        return self.logs.items;
    }
    /// Returns the EIP-3529 refund after the transaction gas-use cap is applied.
    pub fn cappedRefund(self: *const Machine, gas_used: u64) u64 {
        return @min(@as(u64, @intCast(@max(0, self.refund))), gas_used / 5);
    }
    /// Frees transaction-local storage and access lists.
    pub fn deinit(self: *Machine) void {
        self.transient.deinit(self.allocator);
        self.warm.deinit(self.allocator);
        self.warm_accounts.deinit(self.allocator);
        self.original.deinit(self.allocator);
        self.clearLogs(0);
        self.logs.deinit(self.allocator);
    }
    /// Executes one frame, returning owned bytes; only allocator failures escape.
    pub fn run(self: *Machine, input: Input) anyerror!Result {
        if (input.depth >= 1024) return .{ .status = .{ .fault = .depth }, .gas_remaining = 0, .output = try self.allocator.dupe(u8, "") };
        const saved_transient = try self.allocator.dupe(Slot, self.transient.items);
        defer self.allocator.free(saved_transient);
        const saved_warm = try self.allocator.dupe(Key, self.warm.items);
        defer self.allocator.free(saved_warm);
        const saved_accounts = self.warm_accounts.items.len;
        const saved_logs = self.logs.items.len;
        const snap = try self.world.snapshot();
        const saved_refund = self.refund;
        var frame = Frame{ .machine = self, .input = input, .gas = input.gas };
        defer frame.memory.deinit(self.allocator);
        defer frame.return_data.deinit(self.allocator);
        const outcome = frame.execute() catch |err| {
            try self.world.revert(snap);
            try self.restore(saved_transient, saved_warm, saved_accounts, saved_logs, saved_refund);
            if (err == error.OutOfMemory) return err;
            return .{ .status = .{ .fault = switch (err) {
                error.OutOfGas => .out_of_gas,
                error.StackUnderflow => .stack_underflow,
                error.StackOverflow => .stack_overflow,
                error.InvalidJump => .invalid_jump,
                error.WriteProtection => .write_protection,
                error.MemoryOverflow => .memory_overflow,
                error.MissingContext => .missing_context,
                error.UnsupportedPrecompile => .unsupported_precompile,
                else => .invalid_opcode,
            } }, .gas_remaining = 0, .output = try self.allocator.dupe(u8, "") };
        };
        switch (outcome.status) {
            .success => try self.world.commit(snap),
            else => {
                try self.world.revert(snap);
                try self.restore(saved_transient, saved_warm, saved_accounts, saved_logs, saved_refund);
            },
        }
        return outcome;
    }
    /// Restores transaction-local changes made within a reverted frame.
    fn restore(self: *Machine, transient: []const Slot, warm: []const Key, accounts: usize, logs: usize, refund: i128) !void {
        self.transient.clearRetainingCapacity();
        try self.transient.appendSlice(self.allocator, transient);
        self.warm.clearRetainingCapacity();
        try self.warm.appendSlice(self.allocator, warm);
        self.warm_accounts.shrinkRetainingCapacity(accounts);
        self.clearLogs(logs);
        self.refund = refund;
    }
    /// Releases log data created after a frame checkpoint.
    fn clearLogs(self: *Machine, count: usize) void {
        for (self.logs.items[count..]) |log| self.allocator.free(log.data);
        self.logs.shrinkRetainingCapacity(count);
    }
    /// Warms an account and reports whether it was already warm.
    fn touchAccount(self: *Machine, address: state.Address) !bool {
        for (self.warm_accounts.items) |warm| if (same(warm, address)) return true;
        try self.warm_accounts.append(self.allocator, address);
        return false;
    }
    /// Returns the value at a transient key, or zero if unwritten.
    fn transientGet(self: *const Machine, address: state.Address, key: u256) u256 {
        for (self.transient.items) |slot| if (same(slot.address, address) and slot.key == key) return slot.value;
        return 0;
    }
    /// Writes a transaction-local key; zero is retained to shadow prior values.
    fn transientSet(self: *Machine, address: state.Address, key: u256, value: u256) !void {
        for (self.transient.items) |*slot| if (same(slot.address, address) and slot.key == key) {
            slot.value = value;
            return;
        };
        try self.transient.append(self.allocator, .{ .address = address, .key = key, .value = value });
    }
    /// Marks a storage key warm and returns whether it was already accessed.
    fn touch(self: *Machine, address: state.Address, key: u256) !bool {
        for (self.warm.items) |slot| if (same(slot.address, address) and slot.key == key) return true;
        try self.warm.append(self.allocator, .{ .address = address, .key = key });
        return false;
    }
    /// Caches a slot's transaction-original value on first access.
    fn originalValue(self: *Machine, address: state.Address, key: u256) !u256 {
        for (self.original.items) |slot| if (same(slot.address, address) and slot.key == key) return slot.value;
        const value = self.world.getStorage(address, key);
        try self.original.append(self.allocator, .{ .address = address, .key = key, .value = value });
        return value;
    }
};

/// Compares execution addresses without converting their representation.
fn same(a: state.Address, b: state.Address) bool {
    return std.mem.eql(u8, &a, &b);
}

const Frame = struct {
    machine: *Machine,
    input: Input,
    gas: u64,
    pc: usize = 0,
    stack: [1024]u256 = undefined,
    sp: usize = 0,
    memory: std.ArrayList(u8) = .empty,
    return_data: std.ArrayList(u8) = .empty,

    /// Charges an operation before it can mutate frame state.
    fn charge(self: *Frame, cost: u64) error{OutOfGas}!void {
        if (cost > self.gas) return error.OutOfGas;
        self.gas -= cost;
    }
    /// Pushes a word, rejecting the EVM's 1,024-word limit.
    fn push(self: *Frame, value: u256) error{StackOverflow}!void {
        if (self.sp == self.stack.len) return error.StackOverflow;
        self.stack[self.sp] = value;
        self.sp += 1;
    }
    /// Pops a word in top-first operand order.
    fn pop(self: *Frame) error{StackUnderflow}!u256 {
        if (self.sp == 0) return error.StackUnderflow;
        self.sp -= 1;
        return self.stack[self.sp];
    }
    /// Expands zero-filled memory and charges its quadratic word cost.
    fn expand(self: *Frame, offset: u256, length: u256) !usize {
        if (length == 0) return 0;
        const end256 = @addWithOverflow(offset, length);
        if (end256[1] != 0 or end256[0] > std.math.maxInt(usize)) return error.MemoryOverflow;
        const end: usize = @intCast(end256[0]);
        const old_words: u128 = self.memory.items.len / 32;
        const new_words: u128 = (@as(u128, end) + 31) / 32;
        if (new_words > old_words) {
            const old_cost = 3 * old_words + old_words * old_words / 512;
            const new_cost = 3 * new_words + new_words * new_words / 512;
            if (new_cost - old_cost > self.gas) return error.OutOfGas;
            try self.charge(@intCast(new_cost - old_cost));
            const size = new_words * 32;
            if (size > std.math.maxInt(usize)) return error.MemoryOverflow;
            const old_len = self.memory.items.len;
            try self.memory.resize(self.machine.allocator, @intCast(size));
            @memset(self.memory.items[old_len..], 0);
        }
        return @intCast(offset);
    }
    /// Copies a bounded memory range into result-owned bytes.
    fn output(self: *Frame, offset: u256, length: u256, status: Status) !Result {
        const start = try self.expand(offset, length);
        const n: usize = @intCast(length);
        return .{ .status = status, .gas_remaining = self.gas, .output = try self.machine.allocator.dupe(u8, self.memory.items[start..][0..n]) };
    }
    /// Returns true only for JUMPDEST bytes outside PUSH immediates.
    fn jumpdest(self: *const Frame, target: u256) bool {
        if (target > std.math.maxInt(usize)) return false;
        const dest: usize = @intCast(target);
        if (dest >= self.input.code.len) return false;
        var i: usize = 0;
        while (i < self.input.code.len) {
            const op = self.input.code[i];
            if (i == dest) return op == 0x5b;
            i += 1;
            if (op >= 0x60 and op <= 0x7f) i += @as(usize, op - 0x5f);
        }
        return false;
    }
    /// Copies source bytes into expanded memory, padding input beyond its end with zero.
    fn copyToMemory(self: *Frame, dst: u256, src: u256, length: u256, bytes: []const u8, bounded: bool) !void {
        if (bounded and (src > bytes.len or length > bytes.len - @as(usize, @intCast(src)))) return error.InvalidOpcode;
        if (length > std.math.maxInt(u64)) return error.OutOfGas;
        const words = (@as(u128, @intCast(length)) + 31) / 32;
        if (words > std.math.maxInt(u64) / 3) return error.OutOfGas;
        try self.charge(@intCast(words * 3));
        const start = try self.expand(dst, length);
        if (length == 0) return;
        const n: usize = @intCast(length);
        @memset(self.memory.items[start..][0..n], 0);
        if (src < bytes.len) {
            const s: usize = @intCast(src);
            const available = @min(n, bytes.len - s);
            @memcpy(self.memory.items[start..][0..available], bytes[s..][0..available]);
        }
    }
    /// Interprets a stack word as a 160-bit address.
    fn addressFromWord(word: u256) state.Address {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, word, .big);
        return bytes[12..32].*;
    }
    /// Converts an address to an EVM stack word.
    fn addressWord(address: state.Address) u256 {
        return std.mem.readInt(u160, &address, .big);
    }
    /// Reads a 32-byte word from source, padding beyond the end with zero.
    fn sourceWord(bytes: []const u8, offset: u256) u256 {
        if (offset >= bytes.len) return 0;
        const start: usize = @intCast(offset);
        var word: [32]u8 = .{0} ** 32;
        const n = @min(32, bytes.len - start);
        @memcpy(word[0..n], bytes[start..][0..n]);
        return std.mem.readInt(u256, &word, .big);
    }
    /// Executes the environment and external-code opcode range.
    fn contextOpcode(self: *Frame, op: u8) !void {
        const world = self.machine.world;
        switch (op) {
            0x30 => {
                try self.charge(2);
                try self.push(addressWord(self.input.callee));
            },
            0x31, 0x3b, 0x3c, 0x3f => {
                const address = addressFromWord(try self.pop());
                const warm = try self.machine.touchAccount(address);
                try self.charge(if (warm) 100 else 2600);
                switch (op) {
                    0x31 => try self.push(world.getBalance(address)),
                    0x3b => try self.push(world.getCode(address).len),
                    0x3c => {
                        const dst = try self.pop();
                        const src = try self.pop();
                        const len = try self.pop();
                        try self.copyToMemory(dst, src, len, world.getCode(address), false);
                    },
                    0x3f => {
                        const account = try world.getAccount(address);
                        try self.push(if (account) |a| std.mem.readInt(u256, &a.code_hash, .big) else 0);
                    },
                    else => unreachable,
                }
            },
            0x32, 0x3a, 0x40...0x46, 0x48...0x4a => {
                const env = self.machine.environment orelse return error.MissingContext;
                switch (op) {
                    0x32 => {
                        try self.charge(2);
                        try self.push(addressWord(env.origin));
                    },
                    0x3a => {
                        try self.charge(2);
                        try self.push(env.gas_price);
                    },
                    0x40 => {
                        try self.charge(20);
                        const number = try self.pop();
                        const distance = if (number < env.number) @as(u256, env.number) - number else 0;
                        if (distance == 0 or distance > 256) {
                            try self.push(0);
                        } else {
                            const hashes = env.block_hashes orelse return error.MissingContext;
                            if (distance > hashes.len) return error.MissingContext;
                            try self.push(std.mem.readInt(u256, &hashes[@intCast(distance - 1)], .big));
                        }
                    },
                    0x41 => {
                        try self.charge(2);
                        try self.push(addressWord(env.coinbase));
                    },
                    0x42 => {
                        try self.charge(2);
                        try self.push(env.timestamp);
                    },
                    0x43 => {
                        try self.charge(2);
                        try self.push(env.number);
                    },
                    0x44 => {
                        try self.charge(2);
                        try self.push(env.prev_randao);
                    },
                    0x45 => {
                        try self.charge(2);
                        try self.push(env.gas_limit);
                    },
                    0x46 => {
                        try self.charge(2);
                        try self.push(env.chain_id);
                    },
                    0x48 => {
                        try self.charge(2);
                        try self.push(env.base_fee);
                    },
                    0x49 => {
                        try self.charge(3);
                        const index = try self.pop();
                        try self.push(if (index < env.blob_hashes.len) std.mem.readInt(u256, &env.blob_hashes[@intCast(index)], .big) else 0);
                    },
                    0x4a => {
                        try self.charge(2);
                        try self.push(env.blob_base_fee);
                    },
                    else => unreachable,
                }
            },
            0x33 => {
                try self.charge(2);
                try self.push(addressWord(self.input.caller));
            },
            0x34 => {
                try self.charge(2);
                try self.push(self.input.value);
            },
            0x35 => {
                try self.charge(3);
                try self.push(sourceWord(self.input.data, try self.pop()));
            },
            0x36 => {
                try self.charge(2);
                try self.push(self.input.data.len);
            },
            0x37 => {
                try self.charge(3);
                const dst = try self.pop();
                const src = try self.pop();
                const len = try self.pop();
                try self.copyToMemory(dst, src, len, self.input.data, false);
            },
            0x38 => {
                try self.charge(2);
                try self.push(self.input.code.len);
            },
            0x39 => {
                try self.charge(3);
                const dst = try self.pop();
                const src = try self.pop();
                const len = try self.pop();
                try self.copyToMemory(dst, src, len, self.input.code, false);
            },
            0x3d => {
                try self.charge(2);
                try self.push(self.return_data.items.len);
            },
            0x3e => {
                try self.charge(3);
                const dst = try self.pop();
                const src = try self.pop();
                const len = try self.pop();
                try self.copyToMemory(dst, src, len, self.return_data.items, true);
            },
            0x47 => {
                try self.charge(5);
                try self.push(world.getBalance(self.input.callee));
            },
            else => return error.InvalidOpcode,
        }
    }
    /// Appends a log in emission order; frame rollback discards its owned data.
    fn log(self: *Frame, topics_count: u8) !void {
        if (self.input.is_static) return error.WriteProtection;
        const offset = try self.pop();
        const length = try self.pop();
        if (length > std.math.maxInt(u64) / 8) return error.OutOfGas;
        try self.charge(375 + @as(u64, topics_count) * 375 + @as(u64, @intCast(length)) * 8);
        const start = try self.expand(offset, length);
        var topics: [4]state.Hash = .{.{0} ** 32} ** 4;
        for (0..topics_count) |i| std.mem.writeInt(u256, &topics[i], try self.pop(), .big);
        const data = try self.machine.allocator.dupe(u8, self.memory.items[start..][0..@intCast(length)]);
        errdefer self.machine.allocator.free(data);
        try self.machine.logs.append(self.machine.allocator, .{ .address = self.input.callee, .topics = topics, .topic_count = topics_count, .data = data });
    }
    /// Executes a child call with EIP-150 forwarding and frame-local rollback.
    fn call(self: *Frame, op: u8) !void {
        const requested = try self.pop();
        const target = addressFromWord(try self.pop());
        const value: u256 = if (op == 0xf1 or op == 0xf2) try self.pop() else if (op == 0xf4) self.input.value else 0;
        const in_offset = try self.pop();
        const in_len = try self.pop();
        const out_offset = try self.pop();
        const out_len = try self.pop();
        if (self.input.is_static and value != 0 and (op == 0xf1 or op == 0xf2)) return error.WriteProtection;
        const input_start = try self.expand(in_offset, in_len);
        const output_start = try self.expand(out_offset, out_len);
        const warm = try self.machine.touchAccount(target);
        var precompile: state.Address = .{0} ** 20;
        precompile[19] = target[19];
        if (target[19] >= 1 and target[19] <= 0x11 and same(target, precompile)) return error.UnsupportedPrecompile;
        const transfer = (op == 0xf1 or op == 0xf2) and value != 0;
        const account = if (op == 0xf1 and value != 0) try self.machine.world.getAccount(target) else null;
        try self.charge((if (warm) @as(u64, 100) else 2600) + (if (transfer) @as(u64, 9000) else 0) + (if (op == 0xf1 and value != 0 and account == null) @as(u64, 25000) else 0));
        self.return_data.clearRetainingCapacity();
        if (self.input.depth == 1023 or (transfer and self.machine.world.getBalance(self.input.callee) < value)) {
            try self.push(0);
            return;
        }
        const capped = self.gas - self.gas / 64;
        const forwarded: u64 = @intCast(@min(requested, capped));
        const child_gas = forwarded + (if (transfer) @as(u64, 2300) else 0);
        try self.charge(forwarded);
        const snap = try self.machine.world.snapshot();
        var snap_open = true;
        errdefer if (snap_open) self.machine.world.revert(snap) catch {};
        const recipient = if (op == 0xf1 or op == 0xfa) target else self.input.callee;
        if (op == 0xf1 and value != 0) {
            try self.machine.world.setBalance(self.input.callee, self.machine.world.getBalance(self.input.callee) - value);
            try self.machine.world.setBalance(target, self.machine.world.getBalance(target) + value);
        }
        var result = try self.machine.run(.{
            .code = self.machine.world.getCode(target),
            .gas = child_gas,
            .caller = if (op == 0xf4) self.input.caller else self.input.callee,
            .callee = recipient,
            .value = value,
            .data = self.memory.items[input_start..][0..@intCast(in_len)],
            .depth = self.input.depth + 1,
            .is_static = self.input.is_static or op == 0xfa,
        });
        defer result.deinit(self.machine.allocator);
        switch (result.status) {
            .success => {
                try self.machine.world.commit(snap);
                snap_open = false;
                try self.push(1);
            },
            else => {
                try self.machine.world.revert(snap);
                snap_open = false;
                try self.push(0);
            },
        }
        self.gas += result.gas_remaining;
        try self.return_data.appendSlice(self.machine.allocator, result.output);
        const copied = @min(@as(usize, @intCast(out_len)), result.output.len);
        @memcpy(self.memory.items[output_start..][0..copied], result.output[0..copied]);
    }
    /// Executes opcodes until STOP, RETURN, REVERT, or a deterministic fault.
    fn execute(self: *Frame) !Result {
        while (self.pc < self.input.code.len) {
            const op = self.input.code[self.pc];
            self.pc += 1;
            if (op >= 0x60 and op <= 0x7f) {
                try self.charge(3);
                var word: u256 = 0;
                for (0..@as(usize, op - 0x5f)) |_| {
                    word <<= 8;
                    if (self.pc < self.input.code.len) word |= self.input.code[self.pc];
                    self.pc += 1;
                }
                try self.push(word);
                continue;
            }
            if (op >= 0x80 and op <= 0x8f) {
                try self.charge(3);
                const n = @as(usize, op - 0x7f);
                if (self.sp < n) return error.StackUnderflow;
                try self.push(self.stack[self.sp - n]);
                continue;
            }
            if (op >= 0x90 and op <= 0x9f) {
                try self.charge(3);
                const n = @as(usize, op - 0x8f);
                if (self.sp <= n) return error.StackUnderflow;
                std.mem.swap(u256, &self.stack[self.sp - 1], &self.stack[self.sp - 1 - n]);
                continue;
            }
            switch (op) {
                0x00 => return self.output(0, 0, .success),
                0x01...0x0b, 0x10...0x1d => try self.arithmetic(op),
                0x30...0x4a => try self.contextOpcode(op),
                0x50 => {
                    try self.charge(2);
                    _ = try self.pop();
                },
                0x51 => {
                    try self.charge(3);
                    const offset = try self.pop();
                    const start = try self.expand(offset, 32);
                    try self.push(std.mem.readInt(u256, self.memory.items[start..][0..32], .big));
                },
                0x52 => {
                    try self.charge(3);
                    const offset = try self.pop();
                    const value = try self.pop();
                    const start = try self.expand(offset, 32);
                    std.mem.writeInt(u256, self.memory.items[start..][0..32], value, .big);
                },
                0x53 => {
                    try self.charge(3);
                    const offset = try self.pop();
                    const value = try self.pop();
                    const start = try self.expand(offset, 1);
                    self.memory.items[start] = @truncate(value);
                },
                0x54 => {
                    const key = try self.pop();
                    const warm = try self.machine.touch(self.input.callee, key);
                    _ = try self.machine.originalValue(self.input.callee, key);
                    try self.charge(if (warm) 100 else 2100);
                    try self.push(self.machine.world.getStorage(self.input.callee, key));
                },
                0x55 => try self.sstore(),
                0x56 => {
                    try self.charge(8);
                    const dest = try self.pop();
                    if (!self.jumpdest(dest)) return error.InvalidJump;
                    self.pc = @intCast(dest);
                },
                0x57 => {
                    try self.charge(10);
                    const dest = try self.pop();
                    const cond = try self.pop();
                    if (cond != 0) {
                        if (!self.jumpdest(dest)) return error.InvalidJump;
                        self.pc = @intCast(dest);
                    }
                },
                0x58 => {
                    try self.charge(2);
                    try self.push(self.pc - 1);
                },
                0x59 => {
                    try self.charge(2);
                    try self.push(self.memory.items.len);
                },
                0x5a => {
                    try self.charge(2);
                    try self.push(self.gas);
                },
                0x5b => try self.charge(1),
                0x5c => {
                    try self.charge(100);
                    const key = try self.pop();
                    try self.push(self.machine.transientGet(self.input.callee, key));
                },
                0x5d => {
                    if (self.input.is_static) return error.WriteProtection;
                    try self.charge(100);
                    const key = try self.pop();
                    const value = try self.pop();
                    try self.machine.transientSet(self.input.callee, key, value);
                },
                0x5e => {
                    const dst = try self.pop();
                    const src = try self.pop();
                    const len = try self.pop();
                    if (len > std.math.maxInt(u64)) return error.OutOfGas;
                    const words = (@as(u128, @intCast(len)) + 31) / 32;
                    if (words > (std.math.maxInt(u64) - 3) / 3) return error.OutOfGas;
                    try self.charge(@intCast(3 + 3 * words));
                    const d = try self.expand(dst, len);
                    const s = try self.expand(src, len);
                    const n: usize = @intCast(len);
                    if (d < s) std.mem.copyForwards(u8, self.memory.items[d..][0..n], self.memory.items[s..][0..n]) else std.mem.copyBackwards(u8, self.memory.items[d..][0..n], self.memory.items[s..][0..n]);
                },
                0x5f => {
                    try self.charge(2);
                    try self.push(0);
                },
                0xa0...0xa4 => try self.log(op - 0xa0),
                0xf1, 0xf2, 0xf4, 0xfa => try self.call(op),
                0xf3, 0xfd => {
                    const offset = try self.pop();
                    const length = try self.pop();
                    return self.output(offset, length, if (op == 0xf3) .success else .revert);
                },
                else => return error.InvalidOpcode,
            }
        }
        return self.output(0, 0, .success);
    }
    /// Applies the EIP-2200/2929 write charge and records state and refund changes.
    fn sstore(self: *Frame) !void {
        if (self.input.is_static) return error.WriteProtection;
        if (self.gas <= 2300) return error.OutOfGas;
        const key = try self.pop();
        const value = try self.pop();
        const original = try self.machine.originalValue(self.input.callee, key);
        const current = self.machine.world.getStorage(self.input.callee, key);
        const warm = try self.machine.touch(self.input.callee, key);
        const cold: u64 = if (warm) 0 else 2100;
        const cost: u64 = if (value == current) 100 else if (original == current) (if (original == 0) 20000 else 2900) else 100;
        try self.charge(cold + cost);
        if (value != current) {
            if (original == current) {
                if (original != 0 and value == 0) self.machine.refund += 4800;
            } else {
                if (original != 0) {
                    if (current == 0) self.machine.refund -= 4800;
                    if (value == 0) self.machine.refund += 4800;
                }
                if (value == original) self.machine.refund += if (original == 0) @as(i128, 19900) else 2800;
            }
            try self.machine.world.setStorage(self.input.callee, key, value);
        }
    }
    /// Evaluates arithmetic, comparison, bitwise, and shift opcodes on 256-bit words.
    fn arithmetic(self: *Frame, op: u8) !void {
        const cost: u64 = switch (op) {
            0x02, 0x04...0x07, 0x0b => 5,
            0x08, 0x09 => 8,
            0x0a => 10,
            0x01, 0x03, 0x10...0x1d => 3,
            else => return error.InvalidOpcode,
        };
        try self.charge(cost);
        const a = try self.pop();
        const b: u256 = if (op == 0x15 or op == 0x19) 0 else try self.pop();
        const c: u256 = if (op == 0x08 or op == 0x09) try self.pop() else 0;
        const sa: i256 = @bitCast(a);
        const sb: i256 = @bitCast(b);
        const result: u256 = switch (op) {
            0x01 => a +% b,
            0x02 => a *% b,
            0x03 => a -% b,
            0x04 => if (b == 0) 0 else a / b,
            0x05 => if (b == 0) 0 else if (sa == std.math.minInt(i256) and sb == -1) a else @bitCast(@divTrunc(sa, sb)),
            0x06 => if (b == 0) 0 else a % b,
            0x07 => if (b == 0 or b == std.math.maxInt(u256)) 0 else @bitCast(@rem(sa, sb)),
            0x08 => if (c == 0) 0 else @intCast((@as(u512, a) + b) % c),
            0x09 => if (c == 0) 0 else @intCast((@as(u512, a) * b) % c),
            0x0a => blk: {
                var base = a;
                var exponent = b;
                var value: u256 = 1;
                while (exponent != 0) : (exponent >>= 1) {
                    if (exponent & 1 != 0) value *%= base;
                    base *%= base;
                }
                break :blk value;
            },
            0x0b => blk: {
                if (a >= 31) break :blk b;
                const bit: u8 = @intCast(a * 8 + 7);
                const mask: u256 = (@as(u256, 1) << @intCast(bit + 1)) - 1;
                break :blk if (b & (@as(u256, 1) << @intCast(bit)) != 0) b | ~mask else b & mask;
            },
            0x10 => @intFromBool(a < b),
            0x11 => @intFromBool(a > b),
            0x12 => @intFromBool(sa < sb),
            0x13 => @intFromBool(sa > sb),
            0x14 => @intFromBool(a == b),
            0x15 => @intFromBool(a == 0),
            0x16 => a & b,
            0x17 => a | b,
            0x18 => a ^ b,
            0x19 => ~a,
            0x1a => if (a >= 32) 0 else @as(u8, @truncate(b >> @intCast((31 - a) * 8))),
            0x1b => if (a >= 256) 0 else b << @intCast(a),
            0x1c => if (a >= 256) 0 else b >> @intCast(a),
            0x1d => if (a >= 256) (if (sb < 0) std.math.maxInt(u256) else 0) else @bitCast(sb >> @intCast(a)),
            else => unreachable,
        };
        if (op == 0x0a) {
            var exponent = b;
            var bytes: u64 = 0;
            while (exponent != 0) : (exponent >>= 8) bytes += 1;
            try self.charge(bytes * 50);
        }
        try self.push(result);
    }
};

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
    try std.testing.expectEqual(@as(u256, 0), try machine.originalValue(address, 1));
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
    try std.testing.expectEqual(@as(u256, 0), try machine.originalValue(address, 2));
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
    try std.testing.expectEqual(@as(u256, 0), machine.transientGet(child, 2));
}
