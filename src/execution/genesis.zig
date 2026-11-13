// An Osaka genesis fixes the starting account state and execution header.
// Accounts are applied before computing the state root; header fields then
// determine the genesis hash used to guard durable recovery.
// This parser supports a 2 MiB JSON file, 1 MiB per account code, and a
// positive signed-64-bit JSON chain ID.
//
// alloc -> state root -> genesis header -> genesis hash
const std = @import("std");
const execution = @import("execution.zig");

pub const Result = struct { header: execution.Header, chain_id: u256 };

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
    return .{ .header = header, .chain_id = chain_id };
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

/// Decodes bounded hexadecimal genesis bytes.
fn bytesValue(a: std.mem.Allocator, value: std.json.Value, limit: usize) ![]u8 {
    if (value != .string or !std.mem.startsWith(u8, value.string, "0x") or value.string.len % 2 != 0 or (value.string.len - 2) / 2 > limit) return error.InvalidGenesis;
    const result = try a.alloc(u8, (value.string.len - 2) / 2);
    _ = std.fmt.hexToBytes(result, value.string[2..]) catch return error.InvalidGenesis;
    return result;
}
