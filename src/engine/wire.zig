// Engine JSON-RPC uses fixed-length DATA for hashes and canonical QUANTITY for
// numbers. Decode before any execution state changes; malformed fields cannot
// select a head or admit a payload. V1 carries no withdrawals, V2 adds them,
// and V3 adds blob gas fields. Callers select the fork before using this codec.
const std = @import("std");
const fulu = @import("fulu");
const preset = @import("consensus_preset").Config;

pub const Value = std.json.Value;

/// Reads a required object property.
pub fn field(value: Value, name: []const u8) !Value {
    if (value != .object) return error.InvalidParams;
    return value.object.get(name) orelse error.InvalidParams;
}

/// Reads a JSON string without coercion.
pub fn string(value: Value) ![]const u8 {
    return if (value == .string) value.string else error.InvalidParams;
}

/// Decodes a canonical, bounded JSON-RPC quantity.
pub fn quantity(comptime T: type, value: Value) !T {
    const s = try string(value);
    if (s.len < 3 or !std.mem.startsWith(u8, s, "0x") or (s.len > 3 and s[2] == '0')) return error.InvalidParams;
    for (s[2..]) |c| if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return error.InvalidParams;
    return std.fmt.parseInt(T, s[2..], 16) catch error.InvalidParams;
}

/// Decodes an exact-size JSON-RPC DATA value.
pub fn fixed(comptime n: usize, value: Value) ![n]u8 {
    const s = try string(value);
    if (s.len != 2 + 2 * n or !std.mem.startsWith(u8, s, "0x")) return error.InvalidParams;
    var result: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, s[2..]) catch return error.InvalidParams;
    return result;
}

/// Decodes a bounded variable-size JSON-RPC DATA value.
pub fn bytes(a: std.mem.Allocator, value: Value, limit: usize) ![]u8 {
    const s = try string(value);
    if (s.len < 2 or s.len % 2 != 0 or !std.mem.startsWith(u8, s, "0x") or (s.len - 2) / 2 > limit) return error.InvalidParams;
    const result = try a.alloc(u8, (s.len - 2) / 2);
    _ = std.fmt.hexToBytes(result, s[2..]) catch return error.InvalidParams;
    return result;
}

/// Encodes bytes as lowercase JSON-RPC DATA.
pub fn hex(a: std.mem.Allocator, raw: []const u8) !Value {
    const digits = "0123456789abcdef";
    const out = try a.alloc(u8, raw.len * 2 + 2);
    out[0] = '0';
    out[1] = 'x';
    for (raw, 0..) |byte, i| {
        out[2 + i * 2] = digits[byte >> 4];
        out[3 + i * 2] = digits[byte & 15];
    }
    return .{ .string = out };
}

/// Encodes a JSON-RPC quantity without leading zeroes.
pub fn number(a: std.mem.Allocator, value: anytype) !Value {
    return .{ .string = try std.fmt.allocPrint(a, "0x{x}", .{value}) };
}

/// Creates a JSON object in the request arena.
pub fn object() Value {
    return .{ .object = .empty };
}

/// Adds an object member to a JSON value.
pub fn put(a: std.mem.Allocator, target: *Value, key: []const u8, value: Value) !void {
    try target.object.put(a, key, value);
}

/// Creates an array in the request arena.
pub fn array(a: std.mem.Allocator) Value {
    return .{ .array = std.json.Array.init(a) };
}

/// Encodes the fields defined by the chosen execution payload version.
pub fn payloadJson(a: std.mem.Allocator, p: fulu.ExecutionPayload, version: u8) !Value {
    var out = object();
    try put(a, &out, "parentHash", try hex(a, &p.parent_hash));
    try put(a, &out, "feeRecipient", try hex(a, &p.fee_recipient));
    try put(a, &out, "stateRoot", try hex(a, &p.state_root));
    try put(a, &out, "receiptsRoot", try hex(a, &p.receipts_root));
    try put(a, &out, "logsBloom", try hex(a, &p.logs_bloom));
    try put(a, &out, "prevRandao", try hex(a, &p.prev_randao));
    try put(a, &out, "blockNumber", try number(a, p.block_number));
    try put(a, &out, "gasLimit", try number(a, p.gas_limit));
    try put(a, &out, "gasUsed", try number(a, p.gas_used));
    try put(a, &out, "timestamp", try number(a, p.timestamp));
    try put(a, &out, "extraData", try hex(a, p.extra_data.data));
    try put(a, &out, "baseFeePerGas", try number(a, p.base_fee_per_gas));
    try put(a, &out, "blockHash", try hex(a, &p.block_hash));
    var txs = array(a);
    for (p.transactions.data) |raw| try txs.array.append(try hex(a, raw.data));
    try put(a, &out, "transactions", txs);
    if (version >= 2) {
        var withdrawals = array(a);
        for (p.withdrawals.data) |w| {
            var item = object();
            try put(a, &item, "index", try number(a, w.index));
            try put(a, &item, "validatorIndex", try number(a, w.validator_index));
            try put(a, &item, "address", try hex(a, &w.address));
            try put(a, &item, "amount", try number(a, w.amount));
            try withdrawals.array.append(item);
        }
        try put(a, &out, "withdrawals", withdrawals);
    }
    if (version >= 3) {
        try put(a, &out, "blobGasUsed", try number(a, p.blob_gas_used));
        try put(a, &out, "excessBlobGas", try number(a, p.excess_blob_gas));
    }
    return out;
}

/// Decodes required payload fields and enforces version-specific wire shape.
pub fn parsePayload(a: std.mem.Allocator, value: Value, version: u8) !fulu.ExecutionPayload {
    if (value != .object or version < 1 or version > 3) return error.InvalidParams;
    const common = [_][]const u8{ "parentHash", "feeRecipient", "stateRoot", "receiptsRoot", "logsBloom", "prevRandao", "blockNumber", "gasLimit", "gasUsed", "timestamp", "extraData", "baseFeePerGas", "blockHash", "transactions" };
    var keys = value.object.iterator();
    while (keys.next()) |entry| {
        const key = entry.key_ptr.*;
        var allowed = false;
        for (common) |name| if (std.mem.eql(u8, key, name)) {
            allowed = true;
        };
        if (version >= 2 and std.mem.eql(u8, key, "withdrawals")) allowed = true;
        if (version >= 3 and (std.mem.eql(u8, key, "blobGasUsed") or std.mem.eql(u8, key, "excessBlobGas"))) allowed = true;
        if (!allowed) return error.InvalidParams;
    }
    if (version < 2 and value.object.contains("withdrawals")) return error.InvalidParams;
    if (version < 3 and (value.object.contains("blobGasUsed") or value.object.contains("excessBlobGas"))) return error.InvalidParams;
    const txs = try field(value, "transactions");
    if (txs != .array or txs.array.items.len > preset.MAX_TRANSACTIONS_PER_PAYLOAD) return error.InvalidParams;
    const Tx = std.meta.Child(@FieldType(@FieldType(fulu.ExecutionPayload, "transactions"), "data"));
    const transactions = try a.alloc(Tx, txs.array.items.len);
    for (txs.array.items, transactions) |item, *dest| dest.* = .{ .data = try bytes(a, item, preset.MAX_TRANSACTION_BYTES) };
    var withdrawals: []fulu.Withdrawal = &.{};
    if (version >= 2) {
        const ws = try field(value, "withdrawals");
        if (ws != .array or ws.array.items.len > preset.MAX_WITHDRAWALS_PER_PAYLOAD) return error.InvalidParams;
        withdrawals = try a.alloc(fulu.Withdrawal, ws.array.items.len);
        for (ws.array.items, withdrawals) |item, *dest| dest.* = .{
            .index = try quantity(u64, try field(item, "index")),
            .validator_index = try quantity(u64, try field(item, "validatorIndex")),
            .address = try fixed(20, try field(item, "address")),
            .amount = try quantity(u64, try field(item, "amount")),
        };
    }
    return .{
        .parent_hash = try fixed(32, try field(value, "parentHash")),
        .fee_recipient = try fixed(20, try field(value, "feeRecipient")),
        .state_root = try fixed(32, try field(value, "stateRoot")),
        .receipts_root = try fixed(32, try field(value, "receiptsRoot")),
        .logs_bloom = try fixed(256, try field(value, "logsBloom")),
        .prev_randao = try fixed(32, try field(value, "prevRandao")),
        .block_number = try quantity(u64, try field(value, "blockNumber")),
        .gas_limit = try quantity(u64, try field(value, "gasLimit")),
        .gas_used = try quantity(u64, try field(value, "gasUsed")),
        .timestamp = try quantity(u64, try field(value, "timestamp")),
        .extra_data = .{ .data = try bytes(a, try field(value, "extraData"), 32) },
        .base_fee_per_gas = try quantity(u256, try field(value, "baseFeePerGas")),
        .block_hash = try fixed(32, try field(value, "blockHash")),
        .transactions = .{ .data = transactions },
        .withdrawals = .{ .data = withdrawals },
        .blob_gas_used = if (version >= 3) try quantity(u64, try field(value, "blobGasUsed")) else 0,
        .excess_blob_gas = if (version >= 3) try quantity(u64, try field(value, "excessBlobGas")) else 0,
    };
}

test "Engine quantities and fixed data reject malformed values" {
    try std.testing.expectEqual(@as(u64, 0), try quantity(u64, .{ .string = "0x0" }));
    try std.testing.expectError(error.InvalidParams, quantity(u64, .{ .string = "0x00" }));
    try std.testing.expectError(error.InvalidParams, fixed(32, .{ .string = "0x1234" }));
}
