// An Osaka genesis fixes the starting account state and execution header.
// Accounts are applied before computing the state root; header fields then
// determine the genesis hash used to guard durable recovery.
// This parser supports a 2 MiB JSON file, 1 MiB per account code, and a
// positive signed-64-bit JSON chain ID.
//
// alloc -> state root -> genesis header -> genesis hash
const std = @import("std");
const execution = @import("execution.zig");

pub const Result = struct { header: execution.Header, chain_id: u256, forks: execution.fork_id.Schedule, supported_osaka_genesis: bool };

/// Loads the supported Osaka genesis format and its configured chain ID.
pub fn load(a: std.mem.Allocator, io: std.Io, path: []const u8, world: *execution.state.State) !Result {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(2 * 1024 * 1024));
    const parsed = try std.json.parseFromSlice(std.json.Value, a, raw, .{});
    const root = parsed.value;
    const config = try field(root, "config");
    const chain_id = switch (try field(config, "chainId")) {
        .integer => |n| if (n > 0) @as(u256, @intCast(n)) else return error.InvalidGenesis,
        else => return error.InvalidGenesis,
    };
    const accounts = try field(root, "alloc");
    if (accounts != .object) return error.InvalidGenesis;
    var it = accounts.object.iterator();
    while (it.next()) |entry| {
        // SAFETY: hexToBytes fills the address or parsing fails.
        var address: execution.Address = undefined;
        if (entry.key_ptr.*.len != 40) return error.InvalidGenesis;
        _ = try std.fmt.hexToBytes(&address, entry.key_ptr.*);
        const account = entry.value_ptr.*;
        if (account != .object) return error.InvalidGenesis;
        try world.createAccount(address);
        if (account.object.get("balance")) |balance| try world.setBalance(address, try quantity(u256, balance));
        if (account.object.get("nonce")) |nonce| try world.setNonce(address, try quantity(u64, nonce));
        if (account.object.get("code")) |code| {
            const bytes = try bytesValue(a, code, 1024 * 1024);
            _ = try world.setCode(address, bytes);
        }
        if (account.object.get("storage")) |storage| {
            if (storage != .object) return error.InvalidGenesis;
            var slots = storage.object.iterator();
            while (slots.next()) |slot| try world.setStorage(address, try quantity(u256, .{ .string = slot.key_ptr.* }), try quantity(u256, slot.value_ptr.*));
        }
        var fields = account.object.iterator();
        while (fields.next()) |item| {
            if (!allowedField(item.key_ptr.*, &.{ "balance", "nonce", "code", "storage" })) return error.UnsupportedGenesisAccountField;
        }
    }
    const empty_root = try execution.trie.orderedRoot(a, &.{});
    // SAFETY: Keccak fills the digest before use.
    var ommers: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&.{0xc0}, &ommers, .{});
    // SAFETY: SHA-256 fills the digest before use.
    var requests: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&.{}, &requests, .{});
    var header = std.mem.zeroes(execution.Header);
    header.ommers_hash = ommers;
    header.state_root = try world.stateRoot();
    header.transactions_root = empty_root;
    header.receipts_root = empty_root;
    header.withdrawals_root = empty_root;
    header.requests_hash = requests;
    header.gas_limit = try quantity(u64, try field(root, "gasLimit"));
    header.base_fee_per_gas = try quantity(u256, try field(root, "baseFeePerGas"));
    header.timestamp = try quantity(u64, try field(root, "timestamp"));
    header.extra_data = try bytesValue(a, try field(root, "extraData"), 32);
    if (root.object.get("nonce")) |nonce| std.mem.writeInt(u64, &header.nonce, try quantity(u64, nonce), .big);
    if (root.object.get("mixHash")) |mix_hash| header.prev_randao = try fixedValue(32, mix_hash);
    if (root.object.get("coinbase")) |coinbase| header.fee_recipient = try fixedValue(20, coinbase);
    if (root.object.get("difficulty")) |difficulty| header.difficulty = try quantity(u256, difficulty);
    if (root.object.get("number")) |number| header.number = try quantity(u64, number);
    if (root.object.get("gasUsed")) |gas_used| header.gas_used = try quantity(u64, gas_used);
    if (root.object.get("parentHash")) |parent_hash| header.parent_hash = try fixedValue(32, parent_hash);
    if (root.object.get("blobGasUsed")) |blob_gas_used| if (blob_gas_used != .null) {
        header.blob_gas_used = try quantity(u64, blob_gas_used);
    };
    if (root.object.get("excessBlobGas")) |excess_blob_gas| if (excess_blob_gas != .null) {
        header.excess_blob_gas = try quantity(u64, excess_blob_gas);
    };
    if (root.object.get("slotNumber")) |slot| if (slot != .null) return error.UnsupportedGenesisHeaderField;
    var fields = root.object.iterator();
    while (fields.next()) |item| {
        if (!allowedField(item.key_ptr.*, &.{ "config", "alloc", "nonce", "timestamp", "extraData", "gasLimit", "difficulty", "mixHash", "coinbase", "number", "gasUsed", "parentHash", "baseFeePerGas", "excessBlobGas", "blobGasUsed", "slotNumber" })) return error.UnsupportedGenesisHeaderField;
    }
    var forks = execution.fork_id.Schedule{ .genesis = .{0} ** 32, .genesis_time = header.timestamp };
    var config_fields = config.object.iterator();
    while (config_fields.next()) |item| {
        const name = item.key_ptr.*;
        if (std.mem.endsWith(u8, name, "Block") or std.mem.endsWith(u8, name, "Time")) {
            if (!allowedField(name, &.{ "homesteadBlock", "daoForkBlock", "eip150Block", "eip155Block", "eip158Block", "byzantiumBlock", "constantinopleBlock", "petersburgBlock", "istanbulBlock", "muirGlacierBlock", "berlinBlock", "londonBlock", "arrowGlacierBlock", "grayGlacierBlock", "mergeNetsplitBlock", "shanghaiTime", "cancunTime", "pragueTime", "osakaTime" })) return error.UnsupportedExecutionFork;
            if (item.value_ptr.* == .null) continue;
            const activation = switch (item.value_ptr.*) {
                .integer => |value| if (value >= 0) @as(u64, @intCast(value)) else return error.InvalidGenesis,
                else => return error.InvalidGenesis,
            };
            try forks.add(std.mem.endsWith(u8, name, "Time"), activation);
        }
    }
    return .{ .header = header, .chain_id = chain_id, .forks = forks, .supported_osaka_genesis = supportsOsakaGenesis(config, header) };
}

/// Check that the configured rules and blob limits match Hightower's Osaka engine.
fn supportsOsakaGenesis(config: std.json.Value, header: execution.Header) bool {
    if (header.number != 0 or header.difficulty != 0) return false;
    for ([_][]const u8{ "homesteadBlock", "eip150Block", "eip155Block", "eip158Block", "byzantiumBlock", "constantinopleBlock", "petersburgBlock", "istanbulBlock", "muirGlacierBlock", "berlinBlock", "londonBlock", "arrowGlacierBlock", "grayGlacierBlock", "mergeNetsplitBlock" }) |name| {
        const value = config.object.get(name) orelse if (std.mem.eql(u8, name, "mergeNetsplitBlock")) continue else return false;
        if (value != .integer or value.integer != 0) return false;
    }
    for ([_][]const u8{ "shanghaiTime", "cancunTime", "pragueTime", "osakaTime" }) |name| {
        const value = config.object.get(name) orelse return false;
        if (value != .integer or value.integer < 0 or value.integer > header.timestamp) return false;
    }
    const terminal = config.object.get("terminalTotalDifficulty") orelse return false;
    if (terminal != .integer or terminal.integer != 0) return false;
    const schedule = config.object.get("blobSchedule") orelse return false;
    if (schedule != .object or schedule.object.count() != 2) return false;
    for ([_]struct { name: []const u8, target: i64, max: i64, fraction: i64 }{
        .{ .name = "cancun", .target = 3, .max = 6, .fraction = 3_338_477 },
        .{ .name = "prague", .target = 6, .max = 9, .fraction = 5_007_716 },
    }) |expected| {
        const entry = schedule.object.get(expected.name) orelse return false;
        if (entry != .object or entry.object.count() != 3) return false;
        for ([_]struct { name: []const u8, value: i64 }{
            .{ .name = "target", .value = expected.target },
            .{ .name = "max", .value = expected.max },
            .{ .name = "baseFeeUpdateFraction", .value = expected.fraction },
        }) |field_expected| {
            const value = entry.object.get(field_expected.name) orelse return false;
            if (value != .integer or value.integer != field_expected.value) return false;
        }
    }
    return true;
}

/// Checks whether a supplied genesis field belongs to the supported format.
fn allowedField(name: []const u8, allowed: []const []const u8) bool {
    for (allowed) |field_name| if (std.mem.eql(u8, name, field_name)) return true;
    return false;
}

/// Reads a required genesis object field.
fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidGenesis;
    return value.object.get(name) orelse error.InvalidGenesis;
}

/// Decodes a hexadecimal genesis quantity.
fn quantity(comptime T: type, value: std.json.Value) !T {
    if (value != .string or !std.mem.startsWith(u8, value.string, "0x")) return error.InvalidGenesis;
    return std.fmt.parseInt(T, value.string[2..], 16) catch error.InvalidGenesis;
}

/// Decodes a fixed-width hexadecimal header field.
fn fixedValue(comptime n: usize, value: std.json.Value) ![n]u8 {
    if (value != .string or value.string.len != 2 + 2 * n or !std.mem.startsWith(u8, value.string, "0x")) return error.InvalidGenesis;
    // SAFETY: hexToBytes fills all n bytes or parsing fails.
    var result: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value.string[2..]) catch return error.InvalidGenesis;
    return result;
}

/// Decodes bounded hexadecimal genesis bytes.
fn bytesValue(a: std.mem.Allocator, value: std.json.Value, limit: usize) ![]u8 {
    if (value != .string or !std.mem.startsWith(u8, value.string, "0x") or value.string.len % 2 != 0 or (value.string.len - 2) / 2 > limit) return error.InvalidGenesis;
    const result = try a.alloc(u8, (value.string.len - 2) / 2);
    _ = std.fmt.hexToBytes(result, value.string[2..]) catch return error.InvalidGenesis;
    return result;
}
