// The EVM executes one call frame in opcode order. Its 256-bit stack supplies
// operands, memory expands in 32-byte words and is billed before access, and
// persistent storage is billed against its transaction-original value.
// SHA3 hashes a billed memory range with Ethereum Keccak-256.
// A frame snapshot commits on STOP/RETURN and rolls back on REVERT or fault;
// transient storage, logs, and warm accesses follow the same frame boundary. This core
// accepts at most 1,024 stack words and frame depths 0..1,023.
//
// code → stack/memory → storage snapshot → commit or rollback
// shortcut: transaction-local keys scan arrays and frame checkpoints copy them; use indexed journals if profiling shows this is costly.
const std = @import("std");
const builtin = @import("builtin");
const state = @import("../state.zig");

/// Named EVM byte values used by dispatch and opcode-specific gas rules.
const Op = struct {
    const STOP: u8 = 0x00;
    const ADD: u8 = 0x01;
    const MUL: u8 = 0x02;
    const SUB: u8 = 0x03;
    const DIV: u8 = 0x04;
    const SDIV: u8 = 0x05;
    const MOD: u8 = 0x06;
    const SMOD: u8 = 0x07;
    const ADDMOD: u8 = 0x08;
    const MULMOD: u8 = 0x09;
    const EXP: u8 = 0x0a;
    const SIGNEXTEND: u8 = 0x0b;
    const LT: u8 = 0x10;
    const GT: u8 = 0x11;
    const SLT: u8 = 0x12;
    const SGT: u8 = 0x13;
    const EQ: u8 = 0x14;
    const ISZERO: u8 = 0x15;
    const AND: u8 = 0x16;
    const OR: u8 = 0x17;
    const XOR: u8 = 0x18;
    const NOT: u8 = 0x19;
    const BYTE: u8 = 0x1a;
    const SHL: u8 = 0x1b;
    const SHR: u8 = 0x1c;
    const SAR: u8 = 0x1d;
    const SHA3: u8 = 0x20;
    const ADDRESS: u8 = 0x30;
    const BALANCE: u8 = 0x31;
    const ORIGIN: u8 = 0x32;
    const CALLER: u8 = 0x33;
    const CALLVALUE: u8 = 0x34;
    const CALLDATALOAD: u8 = 0x35;
    const CALLDATASIZE: u8 = 0x36;
    const CALLDATACOPY: u8 = 0x37;
    const CODESIZE: u8 = 0x38;
    const CODECOPY: u8 = 0x39;
    const GASPRICE: u8 = 0x3a;
    const EXTCODESIZE: u8 = 0x3b;
    const EXTCODECOPY: u8 = 0x3c;
    const RETURNDATASIZE: u8 = 0x3d;
    const RETURNDATACOPY: u8 = 0x3e;
    const EXTCODEHASH: u8 = 0x3f;
    const BLOCKHASH: u8 = 0x40;
    const COINBASE: u8 = 0x41;
    const TIMESTAMP: u8 = 0x42;
    const NUMBER: u8 = 0x43;
    const PREVRANDAO: u8 = 0x44;
    const GASLIMIT: u8 = 0x45;
    const CHAINID: u8 = 0x46;
    const SELFBALANCE: u8 = 0x47;
    const BASEFEE: u8 = 0x48;
    const BLOBHASH: u8 = 0x49;
    const BLOBBASEFEE: u8 = 0x4a;
    const POP: u8 = 0x50;
    const MLOAD: u8 = 0x51;
    const MSTORE: u8 = 0x52;
    const MSTORE8: u8 = 0x53;
    const SLOAD: u8 = 0x54;
    const SSTORE: u8 = 0x55;
    const JUMP: u8 = 0x56;
    const JUMPI: u8 = 0x57;
    const PC: u8 = 0x58;
    const MSIZE: u8 = 0x59;
    const GAS: u8 = 0x5a;
    const JUMPDEST: u8 = 0x5b;
    const TLOAD: u8 = 0x5c;
    const TSTORE: u8 = 0x5d;
    const MCOPY: u8 = 0x5e;
    const PUSH0: u8 = 0x5f;
    const PUSH1: u8 = 0x60;
    const PUSH32: u8 = 0x7f;
    const DUP1: u8 = 0x80;
    const DUP16: u8 = 0x8f;
    const SWAP1: u8 = 0x90;
    const SWAP16: u8 = 0x9f;
    const LOG0: u8 = 0xa0;
    const LOG4: u8 = 0xa4;
    const CREATE: u8 = 0xf0;
    const CALL: u8 = 0xf1;
    const CALLCODE: u8 = 0xf2;
    const RETURN: u8 = 0xf3;
    const DELEGATECALL: u8 = 0xf4;
    const CREATE2: u8 = 0xf5;
    const STATICCALL: u8 = 0xfa;
    const REVERT: u8 = 0xfd;
    const SELFDESTRUCT: u8 = 0xff;
};

/// Test-only sink for opcodes fetched by the interpreter, including nested frames.
pub const coverage = if (builtin.is_test) struct {
    pub var opcodes: ?*[256]bool = null;
} else struct {};

/// Executable opcode schedules supported by the transaction machine.
pub const Fork = enum { london, cancun, fulu };

/// Host values shared by every frame of one transaction. Block hashes are newest first.
pub const Environment = struct {
    fork: Fork = .fulu,
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
    blob_base_fee_supported: bool = true,
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
pub const Fault = enum { out_of_gas, stack_underflow, stack_overflow, invalid_opcode, invalid_jump, depth, write_protection, memory_overflow, missing_context, unsupported_precompile, unsupported_opcode };
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
        if (environment.fork == .fulu) if (state.delegationTarget(self.world.getCode(recipient))) |target| {
            _ = try self.touchAccount(target);
        };
        _ = try self.touchAccount(environment.coinbase);
        const precompile_count: usize = switch (environment.fork) {
            .london => 9,
            .cancun => 10,
            .fulu => 17,
        };
        for (1..precompile_count + 1) |i| {
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
                error.UnsupportedOpcode => .unsupported_opcode,
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
    pub fn touchAccount(self: *Machine, address: state.Address) !bool {
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
            if (i == dest) return op == Op.JUMPDEST;
            i += 1;
            if (op >= Op.PUSH1 and op <= Op.PUSH32) i += @as(usize, op - Op.PUSH0);
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
            Op.ADDRESS => {
                try self.charge(2);
                try self.push(addressWord(self.input.callee));
            },
            Op.BALANCE, Op.EXTCODESIZE, Op.EXTCODECOPY, Op.EXTCODEHASH => {
                const address = addressFromWord(try self.pop());
                const warm = try self.machine.touchAccount(address);
                try self.charge(if (warm) 100 else 2600);
                switch (op) {
                    Op.BALANCE => try self.push(world.getBalance(address)),
                    Op.EXTCODESIZE => try self.push(world.getCode(address).len),
                    Op.EXTCODECOPY => {
                        const dst = try self.pop();
                        const src = try self.pop();
                        const len = try self.pop();
                        try self.copyToMemory(dst, src, len, world.getCode(address), false);
                    },
                    Op.EXTCODEHASH => {
                        const account = try world.getAccount(address);
                        try self.push(if (account) |a| std.mem.readInt(u256, &a.code_hash, .big) else 0);
                    },
                    else => unreachable,
                }
            },
            Op.ORIGIN, Op.GASPRICE, Op.BLOCKHASH...Op.CHAINID, Op.BASEFEE...Op.BLOBBASEFEE => {
                const env = self.machine.environment orelse return error.MissingContext;
                switch (op) {
                    Op.ORIGIN => {
                        try self.charge(2);
                        try self.push(addressWord(env.origin));
                    },
                    Op.GASPRICE => {
                        try self.charge(2);
                        try self.push(env.gas_price);
                    },
                    Op.BLOCKHASH => {
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
                    Op.COINBASE => {
                        try self.charge(2);
                        try self.push(addressWord(env.coinbase));
                    },
                    Op.TIMESTAMP => {
                        try self.charge(2);
                        try self.push(env.timestamp);
                    },
                    Op.NUMBER => {
                        try self.charge(2);
                        try self.push(env.number);
                    },
                    Op.PREVRANDAO => {
                        try self.charge(2);
                        try self.push(env.prev_randao);
                    },
                    Op.GASLIMIT => {
                        try self.charge(2);
                        try self.push(env.gas_limit);
                    },
                    Op.CHAINID => {
                        try self.charge(2);
                        try self.push(env.chain_id);
                    },
                    Op.BASEFEE => {
                        try self.charge(2);
                        try self.push(env.base_fee);
                    },
                    Op.BLOBHASH => {
                        try self.charge(3);
                        const index = try self.pop();
                        try self.push(if (index < env.blob_hashes.len) std.mem.readInt(u256, &env.blob_hashes[@intCast(index)], .big) else 0);
                    },
                    Op.BLOBBASEFEE => {
                        if (!env.blob_base_fee_supported) return error.UnsupportedOpcode;
                        try self.charge(2);
                        try self.push(env.blob_base_fee);
                    },
                    else => unreachable,
                }
            },
            Op.CALLER => {
                try self.charge(2);
                try self.push(addressWord(self.input.caller));
            },
            Op.CALLVALUE => {
                try self.charge(2);
                try self.push(self.input.value);
            },
            Op.CALLDATALOAD => {
                try self.charge(3);
                try self.push(sourceWord(self.input.data, try self.pop()));
            },
            Op.CALLDATASIZE => {
                try self.charge(2);
                try self.push(self.input.data.len);
            },
            Op.CALLDATACOPY => {
                try self.charge(3);
                const dst = try self.pop();
                const src = try self.pop();
                const len = try self.pop();
                try self.copyToMemory(dst, src, len, self.input.data, false);
            },
            Op.CODESIZE => {
                try self.charge(2);
                try self.push(self.input.code.len);
            },
            Op.CODECOPY => {
                try self.charge(3);
                const dst = try self.pop();
                const src = try self.pop();
                const len = try self.pop();
                try self.copyToMemory(dst, src, len, self.input.code, false);
            },
            Op.RETURNDATASIZE => {
                try self.charge(2);
                try self.push(self.return_data.items.len);
            },
            Op.RETURNDATACOPY => {
                try self.charge(3);
                const dst = try self.pop();
                const src = try self.pop();
                const len = try self.pop();
                try self.copyToMemory(dst, src, len, self.return_data.items, true);
            },
            Op.SELFBALANCE => {
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
        const fixed_cost: u64 = 375 + @as(u64, topics_count) * 375;
        if (length > (std.math.maxInt(u64) - fixed_cost) / 8) return error.OutOfGas;
        try self.charge(fixed_cost + @as(u64, @intCast(length)) * 8);
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
        const value: u256 = if (op == Op.CALL or op == Op.CALLCODE) try self.pop() else if (op == Op.DELEGATECALL) self.input.value else 0;
        const in_offset = try self.pop();
        const in_len = try self.pop();
        const out_offset = try self.pop();
        const out_len = try self.pop();
        if (self.input.is_static and value != 0 and (op == Op.CALL or op == Op.CALLCODE)) return error.WriteProtection;
        const input_start = try self.expand(in_offset, in_len);
        const output_start = try self.expand(out_offset, out_len);
        const warm = try self.machine.touchAccount(target);
        var precompile: state.Address = .{0} ** 20;
        precompile[19] = target[19];
        const precompile_limit: u8 = switch (if (self.machine.environment) |env| env.fork else Fork.fulu) {
            .london => 9,
            .cancun => 10,
            .fulu => 17,
        };
        if (target[19] >= 1 and target[19] <= precompile_limit and same(target, precompile)) return error.UnsupportedPrecompile;
        const transfer = (op == Op.CALL or op == Op.CALLCODE) and value != 0;
        const account = if (op == Op.CALL and value != 0) try self.machine.world.getAccount(target) else null;
        const is_empty = if (account) |a| a.nonce == 0 and a.balance == 0 and std.mem.eql(u8, &a.code_hash, &state.EMPTY_CODE_HASH) else true;
        try self.charge((if (warm) @as(u64, 100) else 2600) + (if (transfer) @as(u64, 9000) else 0) + (if (op == Op.CALL and value != 0 and is_empty) @as(u64, 25000) else 0));
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
        const recipient = if (op == Op.CALL or op == Op.STATICCALL) target else self.input.callee;
        if (op == Op.CALL and value != 0) {
            try self.machine.world.setBalance(self.input.callee, self.machine.world.getBalance(self.input.callee) - value);
            try self.machine.world.setBalance(target, self.machine.world.getBalance(target) + value);
        }
        const designation = state.delegationTarget(self.machine.world.getCode(target));
        if (designation) |address| {
            const target_warm = try self.machine.touchAccount(address);
            try self.charge(if (target_warm) 100 else 2600);
        }
        var result = try self.machine.run(.{
            .code = self.machine.world.getExecutionCode(target),
            .gas = child_gas,
            .caller = if (op == Op.DELEGATECALL) self.input.caller else self.input.callee,
            .callee = recipient,
            .value = value,
            .data = self.memory.items[input_start..][0..@intCast(in_len)],
            .depth = self.input.depth + 1,
            .is_static = self.input.is_static or op == Op.STATICCALL,
        });
        defer result.deinit(self.machine.allocator);
        if (result.status == .fault) {
            if (result.status.fault == .unsupported_precompile) return error.UnsupportedPrecompile;
            if (result.status.fault == .unsupported_opcode) return error.UnsupportedOpcode;
            if (result.status.fault == .missing_context) return error.MissingContext;
        }
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
            if (builtin.is_test) {
                if (coverage.opcodes) |seen| seen[op] = true;
            }
            self.pc += 1;
            if (self.machine.environment) |env| {
                if (env.fork == .london and (op == Op.BLOBHASH or op == Op.BLOBBASEFEE or (op >= Op.TLOAD and op <= Op.PUSH0))) return error.InvalidOpcode;
            }
            if (op >= Op.PUSH1 and op <= Op.PUSH32) {
                try self.charge(3);
                var word: u256 = 0;
                for (0..@as(usize, op - Op.PUSH0)) |_| {
                    word <<= 8;
                    if (self.pc < self.input.code.len) word |= self.input.code[self.pc];
                    self.pc += 1;
                }
                try self.push(word);
                continue;
            }
            if (op >= Op.DUP1 and op <= Op.DUP16) {
                try self.charge(3);
                const n = @as(usize, op - Op.PUSH32);
                if (self.sp < n) return error.StackUnderflow;
                try self.push(self.stack[self.sp - n]);
                continue;
            }
            if (op >= Op.SWAP1 and op <= Op.SWAP16) {
                try self.charge(3);
                const n = @as(usize, op - Op.DUP16);
                if (self.sp <= n) return error.StackUnderflow;
                std.mem.swap(u256, &self.stack[self.sp - 1], &self.stack[self.sp - 1 - n]);
                continue;
            }
            switch (op) {
                Op.STOP => return self.output(0, 0, .success),
                Op.ADD...Op.SIGNEXTEND, Op.LT...Op.SAR => try self.arithmetic(op),
                Op.SHA3 => {
                    const offset = try self.pop();
                    const length = try self.pop();
                    if (length > std.math.maxInt(u64)) return error.OutOfGas;
                    const words = (@as(u128, @intCast(length)) + 31) / 32;
                    if (words > (std.math.maxInt(u64) - 30) / 6) return error.OutOfGas;
                    try self.charge(@intCast(30 + 6 * words));
                    const start = try self.expand(offset, length);
                    const n: usize = @intCast(length);
                    var digest: [32]u8 = undefined;
                    std.crypto.hash.sha3.Keccak256.hash(self.memory.items[start..][0..n], &digest, .{});
                    try self.push(std.mem.readInt(u256, &digest, .big));
                },
                Op.ADDRESS...Op.BLOBBASEFEE => try self.contextOpcode(op),
                Op.POP => {
                    try self.charge(2);
                    _ = try self.pop();
                },
                Op.MLOAD => {
                    try self.charge(3);
                    const offset = try self.pop();
                    const start = try self.expand(offset, 32);
                    try self.push(std.mem.readInt(u256, self.memory.items[start..][0..32], .big));
                },
                Op.MSTORE => {
                    try self.charge(3);
                    const offset = try self.pop();
                    const value = try self.pop();
                    const start = try self.expand(offset, 32);
                    std.mem.writeInt(u256, self.memory.items[start..][0..32], value, .big);
                },
                Op.MSTORE8 => {
                    try self.charge(3);
                    const offset = try self.pop();
                    const value = try self.pop();
                    const start = try self.expand(offset, 1);
                    self.memory.items[start] = @truncate(value);
                },
                Op.SLOAD => {
                    const key = try self.pop();
                    const warm = try self.machine.touch(self.input.callee, key);
                    _ = try self.machine.originalValue(self.input.callee, key);
                    try self.charge(if (warm) 100 else 2100);
                    try self.push(self.machine.world.getStorage(self.input.callee, key));
                },
                Op.SSTORE => try self.sstore(),
                Op.JUMP => {
                    try self.charge(8);
                    const dest = try self.pop();
                    if (!self.jumpdest(dest)) return error.InvalidJump;
                    self.pc = @intCast(dest);
                },
                Op.JUMPI => {
                    try self.charge(10);
                    const dest = try self.pop();
                    const cond = try self.pop();
                    if (cond != 0) {
                        if (!self.jumpdest(dest)) return error.InvalidJump;
                        self.pc = @intCast(dest);
                    }
                },
                Op.PC => {
                    try self.charge(2);
                    try self.push(self.pc - 1);
                },
                Op.MSIZE => {
                    try self.charge(2);
                    try self.push(self.memory.items.len);
                },
                Op.GAS => {
                    try self.charge(2);
                    try self.push(self.gas);
                },
                Op.JUMPDEST => try self.charge(1),
                Op.TLOAD => {
                    try self.charge(100);
                    const key = try self.pop();
                    try self.push(self.machine.transientGet(self.input.callee, key));
                },
                Op.TSTORE => {
                    if (self.input.is_static) return error.WriteProtection;
                    try self.charge(100);
                    const key = try self.pop();
                    const value = try self.pop();
                    try self.machine.transientSet(self.input.callee, key, value);
                },
                Op.MCOPY => {
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
                Op.PUSH0 => {
                    try self.charge(2);
                    try self.push(0);
                },
                Op.CREATE, Op.CREATE2, Op.SELFDESTRUCT => return error.UnsupportedOpcode,
                Op.LOG0...Op.LOG4 => try self.log(op - Op.LOG0),
                Op.CALL, Op.CALLCODE, Op.DELEGATECALL, Op.STATICCALL => try self.call(op),
                Op.RETURN, Op.REVERT => {
                    const offset = try self.pop();
                    const length = try self.pop();
                    return self.output(offset, length, if (op == Op.RETURN) .success else .revert);
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
            Op.MUL, Op.DIV...Op.SMOD, Op.SIGNEXTEND => 5,
            Op.ADDMOD, Op.MULMOD => 8,
            Op.EXP => 10,
            Op.ADD, Op.SUB, Op.LT...Op.SAR => 3,
            else => return error.InvalidOpcode,
        };
        try self.charge(cost);
        const a = try self.pop();
        const b: u256 = if (op == Op.ISZERO or op == Op.NOT) 0 else try self.pop();
        const c: u256 = if (op == Op.ADDMOD or op == Op.MULMOD) try self.pop() else 0;
        const sa: i256 = @bitCast(a);
        const sb: i256 = @bitCast(b);
        const result: u256 = switch (op) {
            Op.ADD => a +% b,
            Op.MUL => a *% b,
            Op.SUB => a -% b,
            Op.DIV => if (b == 0) 0 else a / b,
            Op.SDIV => if (b == 0) 0 else if (sa == std.math.minInt(i256) and sb == -1) a else @bitCast(@divTrunc(sa, sb)),
            Op.MOD => if (b == 0) 0 else a % b,
            Op.SMOD => if (b == 0 or b == std.math.maxInt(u256)) 0 else @bitCast(@rem(sa, sb)),
            Op.ADDMOD => if (c == 0) 0 else @intCast((@as(u512, a) + b) % c),
            Op.MULMOD => if (c == 0) 0 else @intCast((@as(u512, a) * b) % c),
            Op.EXP => blk: {
                var base = a;
                var exponent = b;
                var value: u256 = 1;
                while (exponent != 0) : (exponent >>= 1) {
                    if (exponent & 1 != 0) value *%= base;
                    base *%= base;
                }
                break :blk value;
            },
            Op.SIGNEXTEND => blk: {
                if (a >= 31) break :blk b;
                const bit: u8 = @intCast(a * 8 + 7);
                const mask: u256 = (@as(u256, 1) << @intCast(bit + 1)) - 1;
                break :blk if (b & (@as(u256, 1) << @intCast(bit)) != 0) b | ~mask else b & mask;
            },
            Op.LT => @intFromBool(a < b),
            Op.GT => @intFromBool(a > b),
            Op.SLT => @intFromBool(sa < sb),
            Op.SGT => @intFromBool(sa > sb),
            Op.EQ => @intFromBool(a == b),
            Op.ISZERO => @intFromBool(a == 0),
            Op.AND => a & b,
            Op.OR => a | b,
            Op.XOR => a ^ b,
            Op.NOT => ~a,
            Op.BYTE => if (a >= 32) 0 else @as(u8, @truncate(b >> @intCast((31 - a) * 8))),
            Op.SHL => if (a >= 256) 0 else b << @intCast(a),
            Op.SHR => if (a >= 256) 0 else b >> @intCast(a),
            Op.SAR => if (a >= 256) (if (sb < 0) std.math.maxInt(u256) else 0) else @bitCast(sb >> @intCast(a)),
            else => unreachable,
        };
        if (op == Op.EXP) {
            var exponent = b;
            var bytes: u64 = 0;
            while (exponent != 0) : (exponent >>= 8) bytes += 1;
            try self.charge(bytes * 50);
        }
        try self.push(result);
    }
};
