// Eth/69 peers exchange chain status before announcing pool hashes. A hash
// announcement may trigger one bounded request; the response carries current
// network transaction bytes, including blob sidecars. RLP sizes and counts
// are checked before any transaction enters the shared execution pool. Up to
// 4,096 announced hashes arrive per message; requests use pages of 256.
//
// Hello -> Status -> hashes -> one request -> bounded transactions
const std = @import("std");
const rlp = @import("rlp");
const execution = @import("execution");

pub const version: u64 = 69;
pub const status_code: u8 = 0x10;
pub const transactions_code: u8 = 0x12;
pub const announce_code: u8 = 0x18;
pub const get_code: u8 = 0x19;
pub const pooled_code: u8 = 0x1a;
pub const max_hashes = 256;
pub const max_announced_hashes = 4096;
pub const max_transaction_bytes = 3 * 1024 * 1024;

pub const Status = struct {
    network_id: u64,
    genesis: [32]u8,
    fork_hash: [4]u8,
    next_fork: u64,
    earliest: u64,
    latest: u64,
    head: [32]u8,
    forks: ?execution.fork_id.Schedule = null,
    head_time: u64 = 0,
};

pub const Announcement = struct { tx_type: u8, size: u32, hash: [32]u8 };

pub const Request = struct { id: u64, hashes: [max_hashes][32]u8 = .{.{0} ** 32} ** max_hashes, count: usize = 0 };

pub const Response = struct { id: u64, transactions: [max_hashes][]const u8 = .{&.{}} ** max_hashes, count: usize = 0 };

/// Encode the seven eth/69 status fields in their canonical RLP order.
pub fn encodeStatus(a: std.mem.Allocator, value: Status) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const fork = try list(temp, &.{ try integerBytes(temp, value.fork_hash), try integer(temp, value.next_fork) });
    return list(a, &.{ try integer(temp, version), try integer(temp, value.network_id), try string(temp, &value.genesis), fork, try integer(temp, value.earliest), try integer(temp, value.latest), try string(temp, &value.head) });
}

/// Parse peer status without trusting its chain identity or block range.
pub fn decodeStatus(a: std.mem.Allocator, wire: []const u8) !Status {
    const parts = try splitList(a, wire, 7);
    defer a.free(parts);
    if (parts.len != 7 or try uint(parts[0]) != version) return error.InvalidStatus;
    const fork = try splitList(a, parts[3], 2);
    defer a.free(fork);
    if (fork.len != 2) return error.InvalidStatus;
    const earliest = try uint(parts[4]);
    const latest = try uint(parts[5]);
    if (latest < earliest) return error.InvalidStatus;
    return .{
        .network_id = try uint(parts[1]),
        .genesis = try fixed(32, parts[2]),
        .fork_hash = try fixed(4, fork[0]),
        .next_fork = try uint(fork[1]),
        .earliest = earliest,
        .latest = latest,
        .head = try fixed(32, parts[6]),
    };
}

/// Encode a bounded hash announcement with type and network-byte size metadata.
pub fn encodeAnnouncements(a: std.mem.Allocator, items: []const Announcement) ![]u8 {
    if (items.len > max_announced_hashes) return error.TooManyHashes;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const types = try temp.alloc(u8, items.len);
    const sizes = try temp.alloc([]const u8, items.len);
    const hashes = try temp.alloc([]const u8, items.len);
    for (items, 0..) |item, i| {
        types[i] = item.tx_type;
        sizes[i] = try integer(temp, item.size);
        hashes[i] = try string(temp, &item.hash);
    }
    return list(a, &.{ try string(temp, types), try list(temp, sizes), try list(temp, hashes) });
}

/// Decode at most 256 announced hashes and check matching type and size arrays.
pub fn decodeAnnouncements(a: std.mem.Allocator, wire: []const u8) ![]Announcement {
    const parts = try splitList(a, wire, 3);
    defer a.free(parts);
    if (parts.len != 3) return error.InvalidAnnouncement;
    const types = try payload(parts[0]);
    if (types.len > max_announced_hashes) return error.TooManyHashes;
    const sizes = try splitList(a, parts[1], max_announced_hashes);
    defer a.free(sizes);
    const hashes = try splitList(a, parts[2], max_announced_hashes);
    defer a.free(hashes);
    if (types.len != sizes.len or types.len != hashes.len) return error.InvalidAnnouncement;
    const result = try a.alloc(Announcement, types.len);
    errdefer a.free(result);
    for (result, 0..) |*item, i| {
        const size = try uint(sizes[i]);
        if (size == 0 or size > max_transaction_bytes) return error.InvalidAnnouncement;
        item.* = .{ .tx_type = types[i], .size = @intCast(size), .hash = try fixed(32, hashes[i]) };
    }
    return result;
}

/// Decode directly sent transactions within the pool's count and byte limits.
pub fn decodeTransactions(a: std.mem.Allocator, wire: []const u8) ![][]const u8 {
    const transactions = try splitList(a, wire, max_hashes);
    errdefer a.free(transactions);
    var total: usize = 0;
    for (transactions) |*item| {
        item.* = if (item.*[0] >= 0xc0) item.* else try payload(item.*);
        if (item.*.len == 0 or item.*.len > max_transaction_bytes) return error.TransactionTooLarge;
        total = try std.math.add(usize, total, item.*.len);
        if (total > max_transaction_bytes) return error.TransactionTooLarge;
    }
    return transactions;
}

/// Request only hashes not already present in the local pool.
pub fn encodeRequest(a: std.mem.Allocator, request: Request) ![]u8 {
    if (request.count > max_hashes) return error.TooManyHashes;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const hashes = try temp.alloc([]const u8, request.count);
    for (hashes, request.hashes[0..request.count]) |*encoded, hash| encoded.* = try string(temp, &hash);
    return list(a, &.{ try integer(temp, request.id), try list(temp, hashes) });
}

/// Decode one bounded hash request and its request ID.
pub fn decodeRequest(a: std.mem.Allocator, wire: []const u8) !Request {
    const parts = try splitList(a, wire, 2);
    defer a.free(parts);
    if (parts.len != 2) return error.InvalidRequest;
    const hashes = try splitList(a, parts[1], max_hashes);
    defer a.free(hashes);
    var result: Request = .{ .id = try uint(parts[0]), .count = hashes.len };
    for (hashes, 0..) |hash, i| result.hashes[i] = try fixed(32, hash);
    return result;
}

/// Encode current pool bytes as an eth/69 response to one request ID.
pub fn encodeResponse(a: std.mem.Allocator, response: Response) ![]u8 {
    if (response.count > max_hashes) return error.TooManyTransactions;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const transactions = try temp.alloc([]const u8, response.count);
    for (transactions, response.transactions[0..response.count]) |*encoded, raw| {
        if (raw.len == 0 or raw.len > max_transaction_bytes) return error.TransactionTooLarge;
        encoded.* = if (raw[0] >= 0xc0) raw else try string(temp, raw);
    }
    return list(a, &.{ try integer(temp, response.id), try list(temp, transactions) });
}

/// Decode an eth/69 response and retain borrowed network bytes until the frame is freed.
pub fn decodeResponse(a: std.mem.Allocator, wire: []const u8) !Response {
    const parts = try splitList(a, wire, 2);
    defer a.free(parts);
    if (parts.len != 2) return error.InvalidResponse;
    const transactions = try splitList(a, parts[1], max_hashes);
    defer a.free(transactions);
    var result: Response = .{ .id = try uint(parts[0]), .count = transactions.len };
    for (transactions, 0..) |item, i| {
        result.transactions[i] = if (item[0] >= 0xc0) item else try payload(item);
        if (result.transactions[i].len == 0 or result.transactions[i].len > max_transaction_bytes) return error.TransactionTooLarge;
    }
    return result;
}

/// Read one canonical RLP list and borrow its encoded child item slices.
fn splitList(a: std.mem.Allocator, wire: []const u8, max_items: usize) ![][]const u8 {
    const header = try itemHeader(wire);
    if (header.kind != .list or header.header_len + header.payload_len != wire.len) return error.InvalidRlpList;
    var items: std.ArrayList([]const u8) = .empty;
    errdefer items.deinit(a);
    var at = header.header_len;
    while (at < wire.len) {
        if (items.items.len == max_items) return error.TooManyItems;
        const child = try itemHeader(wire[at..]);
        const length = try std.math.add(usize, child.header_len, child.payload_len);
        if (length > wire.len - at) return error.InvalidRlpList;
        try items.append(a, wire[at .. at + length]);
        at += length;
    }
    return items.toOwnedSlice(a);
}

/// Return an RLP item's prefix and content length without allocation.
fn itemHeader(wire: []const u8) !rlp.decode.Header {
    var reader = std.Io.Reader.fixed(wire);
    return rlp.decode.readHeader(&reader);
}

/// Return one RLP string's canonical payload bytes.
fn payload(item: []const u8) ![]const u8 {
    const header = try itemHeader(item);
    if (header.kind != .string or header.header_len + header.payload_len != item.len) return error.InvalidRlpString;
    return item[header.header_len..];
}

/// Decode a canonical RLP unsigned integer.
fn uint(item: []const u8) !u64 {
    const raw = try payload(item);
    if (raw.len > 8 or (raw.len > 0 and raw[0] == 0)) return error.InvalidInteger;
    var value: u64 = 0;
    for (raw) |byte| value = (value << 8) | byte;
    return value;
}

/// Decode a fixed-length RLP byte string.
fn fixed(comptime size: usize, item: []const u8) ![size]u8 {
    const raw = try payload(item);
    if (raw.len != size) return error.InvalidLength;
    return raw[0..size].*;
}

/// Serialize a canonical RLP unsigned integer.
fn integer(a: std.mem.Allocator, value: anytype) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try rlp.rlp(&writer.writer, value);
    return writer.toOwnedSlice();
}

/// Serialize a canonical RLP byte string.
fn string(a: std.mem.Allocator, value: []const u8) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try rlp.encoding.encodeString(&writer.writer, value);
    return writer.toOwnedSlice();
}

/// Serialize a fixed hash field with RLP string semantics.
fn integerBytes(a: std.mem.Allocator, value: [4]u8) ![]u8 {
    return string(a, &value);
}

/// Prefix and concatenate already RLP-encoded fields into one list.
fn list(a: std.mem.Allocator, fields: []const []const u8) ![]u8 {
    var length: usize = 0;
    for (fields) |field| length = try std.math.add(usize, length, field.len);
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try rlp.encoding.encodeListHeader(&writer.writer, length);
    for (fields) |field| try writer.writer.writeAll(field);
    return writer.toOwnedSlice();
}

test "eth/69 wire messages preserve bounded announcements and typed transactions" {
    const a = std.testing.allocator;
    const local = Status{ .network_id = 1, .genesis = .{1} ** 32, .fork_hash = .{ 1, 2, 3, 4 }, .next_fork = 0, .earliest = 0, .latest = 3, .head = .{2} ** 32 };
    const status = try encodeStatus(a, local);
    defer a.free(status);
    try std.testing.expectEqualDeep(local, try decodeStatus(a, status));
    const announcements = [_]Announcement{.{ .tx_type = 3, .size = 12, .hash = .{3} ** 32 }};
    const announced = try encodeAnnouncements(a, &announcements);
    defer a.free(announced);
    const decoded = try decodeAnnouncements(a, announced);
    defer a.free(decoded);
    try std.testing.expectEqualDeep(&announcements, decoded);
    var request: Request = .{ .id = 42, .count = 1 };
    request.hashes[0] = announcements[0].hash;
    const asked = try encodeRequest(a, request);
    defer a.free(asked);
    const got = try decodeRequest(a, asked);
    try std.testing.expectEqualDeep(request.hashes[0], got.hashes[0]);
    var response: Response = .{ .id = 42, .count = 1 };
    response.transactions[0] = &.{ 3, 0xc0 };
    const supplied = try encodeResponse(a, response);
    defer a.free(supplied);
    const received = try decodeResponse(a, supplied);
    try std.testing.expectEqual(response.id, received.id);
    try std.testing.expectEqualSlices(u8, response.transactions[0], received.transactions[0]);
}

test "eth/69 accepts direct transactions and multi-page hash announcements" {
    const a = std.testing.allocator;
    const raw = [_]u8{ 2, 0xc0 };
    const transaction = try string(a, &raw);
    defer a.free(transaction);
    const wire = try list(a, &.{transaction});
    defer a.free(wire);
    const decoded = try decodeTransactions(a, wire);
    defer a.free(decoded);
    try std.testing.expectEqualSlices(u8, &raw, decoded[0]);
    const items = try a.alloc(Announcement, 300);
    defer a.free(items);
    for (items, 0..) |*item, index| {
        item.* = .{ .tx_type = 2, .size = 100, .hash = .{0} ** 32 };
        std.mem.writeInt(u32, item.hash[0..4], @intCast(index), .big);
    }
    const announced = try encodeAnnouncements(a, items);
    defer a.free(announced);
    const parsed = try decodeAnnouncements(a, announced);
    defer a.free(parsed);
    try std.testing.expectEqual(@as(usize, 300), parsed.len);
    const too_many = try a.alloc(u8, max_announced_hashes + 1);
    defer a.free(too_many);
    @memset(too_many, 2);
    const types = try string(a, too_many);
    defer a.free(types);
    const empty = try list(a, &.{});
    defer a.free(empty);
    const oversized = try list(a, &.{ types, empty, empty });
    defer a.free(oversized);
    try std.testing.expectError(error.TooManyHashes, decodeAnnouncements(a, oversized));
}
