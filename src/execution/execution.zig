// Execution RLP commits ordered transaction, receipt, and header fields to the
// block hash. Receipts record transaction status, cumulative gas, logs, and a
// 2048-bit bloom of each log address and topic; ordered receipt indexes affect
// the root, while bloom bit order follows the Keccak-derived bit positions.
// Typed envelopes prefix their RLP payload with one type byte. Blocks wrap
// typed transactions as RLP strings and keep legacy lists inline. Fulu uses
// Prague's 21-field header, empty ommers, and withdrawals. Transaction sender
// recovery validates signature bounds and chain IDs but does not execute state.
//
// transaction bytes -> block transaction list -> header transactions root
const std = @import("std");
const rlp = @import("rlp");
const tx_crypto = @import("crypto.zig");
pub const crypto = tx_crypto;
const encoding = rlp.encoding;
const decode = rlp.decode;
pub const bloom_filter = @import("bloom_filter");
pub const state = @import("state.zig");
pub const evm = @import("evm.zig");
pub const transition = @import("transition.zig");
pub const kzg = @import("kzg.zig");
pub const pool = @import("pool.zig");
pub const chain = @import("chain.zig");
pub const rpc = @import("rpc.zig");
pub const trie = @import("trie.zig");

/// Ethereum execution address, always 20 bytes on the wire.
pub const Address = [20]u8;
/// Hash or storage key, always 32 bytes on the wire.
pub const Hash = [32]u8;
/// Encoded Bloom filter carried by a header or receipt.
pub const Bloom = bloom_filter.Bloom;
pub const Access = struct { address: Address, storage_keys: []const Hash };
pub const Authorization = struct { chain_id: u256, address: Address, nonce: u64, y_parity: u8, r: u256, s: u256 };
pub const Legacy = struct { nonce: u64, gas_price: u256, gas_limit: u64, to: ?Address, value: u256, data: []const u8, v: u256, r: u256, s: u256 };
pub const AccessList = struct { chain_id: u256, nonce: u64, gas_price: u256, gas_limit: u64, to: ?Address, value: u256, data: []const u8, access_list: []const Access, y_parity: u8, r: u256, s: u256 };
pub const DynamicFee = struct { chain_id: u256, nonce: u64, max_priority_fee_per_gas: u256, max_fee_per_gas: u256, gas_limit: u64, to: ?Address, value: u256, data: []const u8, access_list: []const Access, y_parity: u8, r: u256, s: u256 };
pub const Blob = struct { chain_id: u256, nonce: u64, max_priority_fee_per_gas: u256, max_fee_per_gas: u256, gas_limit: u64, to: Address, value: u256, data: []const u8, access_list: []const Access, max_fee_per_blob_gas: u256, blob_versioned_hashes: []const Hash, y_parity: u8, r: u256, s: u256 };
pub const SetCode = struct { chain_id: u256, nonce: u64, max_priority_fee_per_gas: u256, max_fee_per_gas: u256, gas_limit: u64, destination: Address, value: u256, data: []const u8, access_list: []const Access, authorization_list: []const Authorization, y_parity: u8, r: u256, s: u256 };
/// Supported transaction envelopes; the tag selects the RLP payload schema.
pub const Transaction = union(enum) { legacy: Legacy, access_list: AccessList, dynamic_fee: DynamicFee, blob: Blob, set_code: SetCode };

/// Prague/Fulu header fields in the exact order committed by execution RLP.
pub const Header = struct {
    parent_hash: Hash,
    ommers_hash: Hash,
    fee_recipient: Address,
    state_root: Hash,
    transactions_root: Hash,
    receipts_root: Hash,
    logs_bloom: Bloom,
    difficulty: u256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    prev_randao: Hash,
    nonce: [8]u8,
    base_fee_per_gas: u256,
    withdrawals_root: Hash,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    parent_beacon_block_root: Hash,
    requests_hash: Hash,
};
pub const Withdrawal = struct { index: u64, validator_index: u64, address: Address, amount: u64 };
pub const Log = struct { address: Address, topics: []const Hash, data: []const u8 };
pub const ReceiptPayload = struct { status: u8, cumulative_gas_used: u64, logs_bloom: Bloom, logs: []const Log };
/// Receipt envelope with the same type byte as its transaction.
pub const Receipt = union(enum) { legacy: ReceiptPayload, access_list: ReceiptPayload, dynamic_fee: ReceiptPayload, blob: ReceiptPayload, set_code: ReceiptPayload };
/// Post-Merge block body: header, transactions, empty ommers, withdrawals.
pub const Block = struct { header: Header, transactions: []const Transaction, withdrawals: []const Withdrawal };

/// Builds a logs bloom from each log address and topic; log data is not indexed.
pub fn logsBloom(logs: []const Log) Bloom {
    var filter = bloom_filter.BloomFilter.init();
    for (logs) |log| {
        filter.add(&log.address);
        for (log.topics) |topic| filter.add(&topic);
    }
    return filter.bits;
}

/// Builds the block bloom by combining the blooms of all receipt logs.
pub fn receiptsBloom(receipts: []const Receipt) Bloom {
    var bloom = [_]u8{0} ** 256;
    for (receipts) |receipt| {
        const logs = switch (receipt) {
            inline else => |payload| payload.logs,
        };
        const receipt_bloom = logsBloom(logs);
        for (&bloom, receipt_bloom) |*dst, bits| dst.* |= bits;
    }
    return bloom;
}

/// Computes the ordered receipts trie root using each receipt's canonical legacy or typed encoding.
pub fn receiptsRoot(allocator: std.mem.Allocator, receipts: []const Receipt) !Hash {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const values = try a.alloc([]const u8, receipts.len);
    for (receipts, 0..) |receipt, i| values[i] = try encode(a, receipt);
    return trie.orderedRoot(a, values);
}

/// Parsed value whose variable-length fields belong to one arena.
pub fn Decoded(comptime T: type) type {
    return struct {
        value: T,
        arena: std.heap.ArenaAllocator,
        /// Releases every slice owned by the decoded value.
        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
        }
    };
}

pub const Error = decode.Error || error{ InvalidShape, InvalidLength, UnknownTransactionType };

/// Maps a transaction or receipt variant to its EIP-2718 type byte.
fn typeByte(tx: anytype) u8 {
    return switch (tx) {
        .legacy => 0,
        .access_list => 1,
        .dynamic_fee => 2,
        .blob => 3,
        .set_code => 4,
    };
}

/// Writes an execution field, using struct declaration order for RLP lists.
fn writeValue(w: *std.Io.Writer, value: anytype) anyerror!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .optional => {
            if (value) |v| try writeValue(w, v) else try encoding.encodeString(w, "");
        },
        .int => try rlp.rlp(w, value),
        .array => |a| {
            if (a.child == u8) try rlp.rlp(w, value) else try writeList(w, value);
        },
        .pointer => |p| {
            if (p.size != .slice) @compileError("unsupported pointer");
            if (p.child == u8) try rlp.rlp(w, value) else try writeList(w, value);
        },
        .@"struct" => {
            var scratch: [64]u8 = undefined;
            var counter: std.Io.Writer.Discarding = .init(&scratch);
            inline for (std.meta.fields(T)) |field| try writeValue(&counter.writer, @field(value, field.name));
            try encoding.encodeListHeader(w, @intCast(counter.fullCount()));
            inline for (std.meta.fields(T)) |field| try writeValue(w, @field(value, field.name));
        },
        else => @compileError("unsupported execution RLP type: " ++ @typeName(T)),
    }
}

/// Measures list payload first so its RLP prefix has the exact byte length.
fn writeList(w: *std.Io.Writer, values: anytype) anyerror!void {
    var scratch: [64]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&scratch);
    for (values) |item| try writeValue(&counter.writer, item);
    try encoding.encodeListHeader(w, @intCast(counter.fullCount()));
    for (values) |item| try writeValue(w, item);
}

/// Writes legacy RLP directly or prefixes a typed transaction's RLP payload.
fn writeTransaction(w: *std.Io.Writer, tx: Transaction) !void {
    if (typeByte(tx) != 0) try w.writeByte(typeByte(tx));
    switch (tx) {
        inline else => |payload| try writeValue(w, payload),
    }
}

/// Writes a receipt with its transaction type byte when applicable.
fn writeReceipt(w: *std.Io.Writer, receipt: Receipt) !void {
    if (typeByte(receipt) != 0) try w.writeByte(typeByte(receipt));
    switch (receipt) {
        inline else => |payload| try writeValue(w, payload),
    }
}

/// Measures and writes the four-item post-Merge block list.
fn writeBlock(w: *std.Io.Writer, block: Block) !void {
    var scratch: [64]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&scratch);
    try writeBlockItems(&counter.writer, block);
    try encoding.encodeListHeader(w, @intCast(counter.fullCount()));
    try writeBlockItems(w, block);
}

/// Keeps the ommers slot empty and withdrawals after it in block RLP.
fn writeBlockItems(w: *std.Io.Writer, block: Block) !void {
    try writeValue(w, block.header);
    var scratch: [64]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&scratch);
    for (block.transactions) |tx| try writeBlockTransaction(&counter.writer, tx);
    try encoding.encodeListHeader(w, @intCast(counter.fullCount()));
    for (block.transactions) |tx| try writeBlockTransaction(w, tx);
    try encoding.encodeListHeader(w, 0);
    try writeValue(w, block.withdrawals);
}

/// Wraps typed transaction bytes as an RLP string inside a block list.
fn writeBlockTransaction(w: *std.Io.Writer, tx: Transaction) !void {
    if (typeByte(tx) == 0) return writeTransaction(w, tx);
    var scratch: [64]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&scratch);
    try writeTransaction(&counter.writer, tx);
    const len: usize = @intCast(counter.fullCount());
    const bytes = try std.heap.page_allocator.alloc(u8, len);
    defer std.heap.page_allocator.free(bytes);
    var fixed: std.Io.Writer = .fixed(bytes);
    try writeTransaction(&fixed, tx);
    try encoding.encodeString(w, bytes);
}

/// Allocates one canonical RLP encoding; the caller frees the returned bytes.
pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const T = @TypeOf(value);
    var scratch: [64]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&scratch);
    if (T == Transaction) try writeTransaction(&counter.writer, value) else if (T == Receipt) try writeReceipt(&counter.writer, value) else if (T == Block) try writeBlock(&counter.writer, value) else try writeValue(&counter.writer, value);
    const out = try allocator.alloc(u8, @intCast(counter.fullCount()));
    errdefer allocator.free(out);
    var fixed: std.Io.Writer = .fixed(out);
    if (T == Transaction) try writeTransaction(&fixed, value) else if (T == Receipt) try writeReceipt(&fixed, value) else if (T == Block) try writeBlock(&fixed, value) else try writeValue(&fixed, value);
    return out;
}

/// Requires an RLP list and, when supplied, its exact field count.
fn asList(value: decode.Value, len: ?usize) Error![]decode.Value {
    const items = switch (value) {
        .list => |v| v,
        else => return error.InvalidShape,
    };
    if (len) |n| if (items.len != n) return error.InvalidShape;
    return items;
}
/// Requires an RLP byte string rather than a nested list.
fn asString(value: decode.Value) Error![]u8 {
    return switch (value) {
        .string => |v| v,
        else => error.InvalidShape,
    };
}

/// Converts a canonical RLP tree to a schema type, checking widths and shapes.
fn fromValue(comptime T: type, allocator: std.mem.Allocator, value: decode.Value) Error!T {
    switch (@typeInfo(T)) {
        .int => {
            const bytes = try asString(value);
            if (bytes.len > 0 and bytes[0] == 0) return error.NonCanonicalInteger;
            if (bytes.len > @sizeOf(T)) return error.IntegerOverflow;
            var result: u256 = 0;
            for (bytes) |b| result = (result << 8) | b;
            return @intCast(result);
        },
        .optional => |o| {
            const bytes = try asString(value);
            if (bytes.len == 0) return null;
            return try fromValue(o.child, allocator, value);
        },
        .array => |a| {
            if (a.child != u8) @compileError("unsupported fixed array");
            const bytes = try asString(value);
            if (bytes.len != a.len) return error.InvalidLength;
            return bytes[0..a.len].*;
        },
        .pointer => |p| {
            if (p.size != .slice) @compileError("unsupported pointer");
            if (p.child == u8) return try allocator.dupe(u8, try asString(value));
            const items = try asList(value, null);
            const out = try allocator.alloc(p.child, items.len);
            for (items, 0..) |item, i| out[i] = try fromValue(p.child, allocator, item);
            return out;
        },
        .@"struct" => {
            const fields = std.meta.fields(T);
            const items = try asList(value, fields.len);
            var out: T = undefined;
            inline for (fields, 0..) |field, i| @field(out, field.name) = try fromValue(field.type, allocator, items[i]);
            return out;
        },
        else => @compileError("unsupported execution decode type: " ++ @typeName(T)),
    }
}

/// Dispatches a standalone transaction by envelope byte, rejecting unknown types.
fn parseTransaction(allocator: std.mem.Allocator, bytes: []const u8) Error!Transaction {
    if (bytes.len == 0) return error.Truncated;
    const typed = bytes[0] < 0x80;
    const tag: u8 = if (typed) bytes[0] else 0;
    if (typed and (tag == 0 or tag > 4)) return error.UnknownTransactionType;
    const payload = if (tag == 0) bytes else bytes[1..];
    var value = try decode.decodeAll(allocator, payload);
    defer value.deinit(allocator);
    return switch (tag) {
        0 => .{ .legacy = try fromValue(Legacy, allocator, value) },
        1 => .{ .access_list = try fromValue(AccessList, allocator, value) },
        2 => .{ .dynamic_fee = try fromValue(DynamicFee, allocator, value) },
        3 => .{ .blob = try fromValue(Blob, allocator, value) },
        4 => .{ .set_code = try fromValue(SetCode, allocator, value) },
        else => unreachable,
    };
}

/// Dispatches a standalone receipt using the corresponding transaction tag.
fn parseReceipt(allocator: std.mem.Allocator, bytes: []const u8) Error!Receipt {
    if (bytes.len == 0) return error.Truncated;
    const typed = bytes[0] < 0x80;
    const tag: u8 = if (typed) bytes[0] else 0;
    if (typed and (tag == 0 or tag > 4)) return error.UnknownTransactionType;
    var value = try decode.decodeAll(allocator, if (tag == 0) bytes else bytes[1..]);
    defer value.deinit(allocator);
    const payload = try fromValue(ReceiptPayload, allocator, value);
    return switch (tag) {
        0 => .{ .legacy = payload },
        1 => .{ .access_list = payload },
        2 => .{ .dynamic_fee = payload },
        3 => .{ .blob = payload },
        4 => .{ .set_code = payload },
        else => unreachable,
    };
}

/// Parses a block's four fields and rejects any nonempty ommers list.
fn parseBlock(allocator: std.mem.Allocator, value: decode.Value) Error!Block {
    const items = try asList(value, 4);
    _ = try asList(items[2], 0);
    const transactions = try asList(items[1], null);
    const txs = try allocator.alloc(Transaction, transactions.len);
    for (transactions, 0..) |item, i| {
        const bytes = switch (item) {
            .string => |v| v,
            .list => {
                txs[i] = .{ .legacy = try fromValue(Legacy, allocator, item) };
                continue;
            },
        };
        if (bytes.len == 0 or bytes[0] == 0 or bytes[0] >= 0x80) return error.InvalidShape;
        txs[i] = try parseTransaction(allocator, bytes);
    }
    return .{
        .header = try fromValue(Header, allocator, items[0]),
        .transactions = txs,
        .withdrawals = try fromValue([]const Withdrawal, allocator, items[3]),
    };
}

/// Parses exactly one value and returns arena-owned fields; call `deinit`.
pub fn parse(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) Error!Decoded(T) {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const result: T = if (T == Transaction) try parseTransaction(a, bytes) else if (T == Receipt) try parseReceipt(a, bytes) else blk: {
        var value = try decode.decodeAll(a, bytes);
        defer value.deinit(a);
        if (T == Block) break :blk try parseBlock(a, value);
        break :blk try fromValue(T, a, value);
    };
    return .{ .value = result, .arena = arena };
}

const SigningDetails = struct { hash: Hash, parity: u8, r: u256, s: u256 };

/// EXPERIMENTAL: Recovers a sender after checking its chain ID; fixture coverage is limited and this is not audited.
pub fn recoverSender(allocator: std.mem.Allocator, transaction: Transaction, expected_chain_id: u256) !Address {
    const signature = try transactionSigningDetails(allocator, transaction, expected_chain_id);
    return tx_crypto.recoverAddress(signature.hash, signature.r, signature.s, signature.parity);
}

/// Builds the fork-independent signing hash and signature fields for one supported transaction envelope.
fn transactionSigningDetails(allocator: std.mem.Allocator, transaction: Transaction, expected_chain_id: u256) !SigningDetails {
    return switch (transaction) {
        .legacy => |tx| blk: {
            const parity: u8 = if (tx.v == 27 or tx.v == 28) blk2: {
                break :blk2 @intCast(tx.v - 27);
            } else if (tx.v >= 35) blk2: {
                const encoded_chain_id = (tx.v - 35) / 2;
                if (encoded_chain_id != expected_chain_id) return error.ChainIdMismatch;
                break :blk2 @intCast((tx.v - 35) % 2);
            } else return error.InvalidV;

            const hash = if (tx.v == 27 or tx.v == 28)
                try hashRlp(allocator, null, .{ tx.nonce, tx.gas_price, tx.gas_limit, tx.to, tx.value, tx.data })
            else
                try hashRlp(allocator, null, .{ tx.nonce, tx.gas_price, tx.gas_limit, tx.to, tx.value, tx.data, (tx.v - 35) / 2, @as(u8, 0), @as(u8, 0) });
            break :blk .{ .hash = hash, .parity = parity, .r = tx.r, .s = tx.s };
        },
        .access_list => |tx| typedDetails(allocator, expected_chain_id, 1, tx.chain_id, tx.y_parity, tx.r, tx.s, .{
            tx.chain_id, tx.nonce, tx.gas_price, tx.gas_limit, tx.to, tx.value, tx.data, tx.access_list,
        }),
        .dynamic_fee => |tx| typedDetails(allocator, expected_chain_id, 2, tx.chain_id, tx.y_parity, tx.r, tx.s, .{
            tx.chain_id, tx.nonce, tx.max_priority_fee_per_gas, tx.max_fee_per_gas, tx.gas_limit, tx.to, tx.value, tx.data, tx.access_list,
        }),
        .blob => |tx| typedDetails(allocator, expected_chain_id, 3, tx.chain_id, tx.y_parity, tx.r, tx.s, .{
            tx.chain_id, tx.nonce, tx.max_priority_fee_per_gas, tx.max_fee_per_gas, tx.gas_limit, tx.to, tx.value, tx.data, tx.access_list, tx.max_fee_per_blob_gas, tx.blob_versioned_hashes,
        }),
        .set_code => |tx| typedDetails(allocator, expected_chain_id, 4, tx.chain_id, tx.y_parity, tx.r, tx.s, .{
            tx.chain_id, tx.nonce, tx.max_priority_fee_per_gas, tx.max_fee_per_gas, tx.gas_limit, tx.destination, tx.value, tx.data, tx.access_list, tx.authorization_list,
        }),
    };
}

/// Validates typed-envelope signature metadata and hashes its unsigned RLP payload.
fn typedDetails(allocator: std.mem.Allocator, expected_chain_id: u256, envelope: u8, chain_id: u256, parity: u8, r: u256, s: u256, payload: anytype) !SigningDetails {
    if (chain_id != expected_chain_id) return error.ChainIdMismatch;
    if (parity > 1) return error.InvalidYParity;
    return .{ .hash = try hashRlp(allocator, envelope, payload), .parity = parity, .r = r, .s = s };
}

/// Hashes an RLP signing payload, prepending its EIP-2718 envelope byte when present.
fn hashRlp(allocator: std.mem.Allocator, envelope: ?u8, payload: anytype) !Hash {
    const encoded = try encode(allocator, payload);
    defer allocator.free(encoded);
    var hash: Hash = undefined;
    if (envelope) |tag| {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&.{tag});
        hasher.update(encoded);
        hasher.final(&hash);
    } else {
        std.crypto.hash.sha3.Keccak256.hash(encoded, &hash, .{});
    }
    return hash;
}
