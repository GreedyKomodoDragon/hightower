// Ethereum Node Records bind a discovery identity, network endpoint, fork
// schedule, and custody promise to one secp256k1 signature. Peers must verify
// the signature and fork fields before using an advertised address. The record
// is capped at 300 encoded bytes; its keys are sorted and unique.
//
//   RLP record -> verify signature -> fork/custody gate -> discovery candidate
const std = @import("std");
const rlp = @import("rlp");
const columns = @import("data_columns.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Keccak = std.crypto.hash.sha3.Keccak256;

pub const Local = struct {
    sequence: u64,
    ip: [4]u8,
    udp_port: u16,
    tcp_port: u16,
    fork_id: [16]u8,
    next_fork_digest: [4]u8,
    custody_group_count: u64,
};

pub const Record = struct {
    node_id: [32]u8,
    public_key: [33]u8,
    sequence: u64,
    ip: [4]u8,
    udp_port: u16,
    tcp_port: u16,
    fork_id: [16]u8,
    next_fork_digest: [4]u8,
    custody_group_count: u64,
};

/// Encode a locally signed, IPv4 Fulu ENR; the caller owns the returned bytes.
pub fn encode(allocator: std.mem.Allocator, key_pair: Ecdsa.KeyPair, record: Local) ![]u8 {
    if (record.custody_group_count < columns.custody_requirement or record.custody_group_count > columns.column_count) return error.InvalidCustodyCount;
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    try writeInt(&payload.writer, record.sequence);
    try writePair(&payload.writer, "cgc", record.custody_group_count);
    try writePair(&payload.writer, "eth2", &record.fork_id);
    try writePair(&payload.writer, "id", "v4");
    try writePair(&payload.writer, "ip", &record.ip);
    try writePair(&payload.writer, "nfd", &record.next_fork_digest);
    const public_key = key_pair.public_key.toCompressedSec1();
    try writePair(&payload.writer, "secp256k1", &public_key);
    try writePair(&payload.writer, "tcp", record.tcp_port);
    try writePair(&payload.writer, "udp", record.udp_port);
    const content = try wrapList(allocator, payload.written());
    defer allocator.free(content);
    var digest: [32]u8 = undefined;
    Keccak.hash(content, &digest, .{});
    const signature = (try key_pair.signPrehashed(digest, null)).toBytes();
    var signed = std.Io.Writer.Allocating.init(allocator);
    defer signed.deinit();
    try rlp.encoding.encodeString(&signed.writer, &signature);
    try signed.writer.writeAll(payload.written());
    const bytes = try wrapList(allocator, signed.written());
    if (bytes.len > 300) {
        allocator.free(bytes);
        return error.RecordTooLarge;
    }
    return bytes;
}

/// Parse and authenticate one bounded ENR before exposing its endpoint.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Record {
    if (bytes.len > 300) return error.RecordTooLarge;
    var value = try rlp.decode.decodeAll(allocator, bytes);
    defer value.deinit(allocator);
    const items = switch (value) {
        .list => |list| list,
        else => return error.InvalidRecord,
    };
    if (items.len < 4 or items.len % 2 != 0) return error.InvalidRecord;
    const signature = try string(items[0]);
    if (signature.len != 64) return error.InvalidSignature;
    var record: Record = undefined;
    record.sequence = try integer(u64, try string(items[1]));
    var seen: u8 = 0;
    var prior: []const u8 = "";
    for (1..items.len / 2) |pair_index| {
        const key = try string(items[pair_index * 2]);
        const data = try string(items[pair_index * 2 + 1]);
        if (key.len == 0 or (pair_index > 1 and std.mem.order(u8, prior, key) != .lt)) return error.InvalidRecord;
        prior = key;
        if (std.mem.eql(u8, key, "cgc")) {
            record.custody_group_count = try integer(u64, data);
            seen |= 1;
        } else if (std.mem.eql(u8, key, "eth2")) {
            if (data.len != 16) return error.InvalidForkContext;
            record.fork_id = data[0..16].*;
            seen |= 2;
        } else if (std.mem.eql(u8, key, "id")) {
            if (!std.mem.eql(u8, data, "v4")) return error.InvalidIdentity;
            seen |= 4;
        } else if (std.mem.eql(u8, key, "ip")) {
            if (data.len != 4) return error.InvalidEndpoint;
            record.ip = data[0..4].*;
            seen |= 8;
        } else if (std.mem.eql(u8, key, "nfd")) {
            if (data.len != 4) return error.InvalidForkContext;
            record.next_fork_digest = data[0..4].*;
            seen |= 16;
        } else if (std.mem.eql(u8, key, "secp256k1")) {
            if (data.len != 33) return error.InvalidIdentity;
            record.public_key = data[0..33].*;
            seen |= 32;
        } else if (std.mem.eql(u8, key, "tcp")) {
            record.tcp_port = try integer(u16, data);
            seen |= 64;
        } else if (std.mem.eql(u8, key, "udp")) {
            record.udp_port = try integer(u16, data);
            seen |= 128;
        }
    }
    if (seen != 255 or record.custody_group_count < columns.custody_requirement or record.custody_group_count > columns.column_count or record.udp_port == 0 or record.tcp_port == 0) return error.InvalidRecord;
    const public_key = try Ecdsa.PublicKey.fromSec1(&record.public_key);
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    for (items[1..]) |item| try rlp.encoding.encodeString(&payload.writer, try string(item));
    const content = try wrapList(allocator, payload.written());
    defer allocator.free(content);
    var digest: [32]u8 = undefined;
    Keccak.hash(content, &digest, .{});
    try Ecdsa.Signature.fromBytes(signature[0..64].*).verifyPrehashed(digest, public_key);
    const uncompressed = public_key.toUncompressedSec1();
    Keccak.hash(uncompressed[1..], &record.node_id, .{});
    return record;
}

/// Reject records from a different current fork before dialing them.
pub fn requireFork(record: Record, fork_digest: [4]u8) !void {
    if (!std.mem.eql(u8, record.fork_id[0..4], &fork_digest)) return error.InvalidForkContext;
}

/// Return the byte string in an RLP item.
fn string(value: rlp.decode.Value) ![]const u8 {
    return switch (value) {
        .string => |bytes| bytes,
        else => error.InvalidRecord,
    };
}

/// Decode a canonical big-endian ENR integer.
fn integer(comptime T: type, bytes: []const u8) !T {
    if (bytes.len > @sizeOf(T) or (bytes.len > 0 and bytes[0] == 0)) return error.InvalidRecord;
    var value: T = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

/// Encode one ENR key and its byte or integer value.
fn writePair(writer: *std.Io.Writer, key: []const u8, value: anytype) !void {
    try rlp.encoding.encodeString(writer, key);
    if (@typeInfo(@TypeOf(value)) == .int) {
        try writeInt(writer, value);
    } else {
        try rlp.encoding.encodeString(writer, value);
    }
}

/// Write one minimal big-endian RLP integer.
fn writeInt(writer: *std.Io.Writer, value: anytype) !void {
    var buffer: [8]u8 = undefined;
    try rlp.encoding.encodeString(writer, rlp.encoding.encodeBigEndian(&buffer, value));
}

/// Add an RLP list header to already encoded item bytes.
fn wrapList(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    try rlp.encoding.encodeListHeader(&output.writer, payload.len);
    try output.writer.writeAll(payload);
    return output.toOwnedSlice();
}

test "signed Fulu ENR verifies its identity, fork, and custody promise" {
    const allocator = std.testing.allocator;
    const key_pair = try Ecdsa.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const record = Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 9000, .tcp_port = 9001, .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = columns.custody_requirement };
    const bytes = try encode(allocator, key_pair, record);
    defer allocator.free(bytes);
    const parsed = try decode(allocator, bytes);
    try std.testing.expectEqual(record.custody_group_count, parsed.custody_group_count);
    try requireFork(parsed, .{ 1, 2, 3, 4 });
    try std.testing.expectError(error.InvalidForkContext, requireFork(parsed, .{ 9, 2, 3, 4 }));
    var invalid_custody = record;
    invalid_custody.custody_group_count = columns.custody_requirement - 1;
    try std.testing.expectError(error.InvalidCustodyCount, encode(allocator, key_pair, invalid_custody));
    try std.testing.expectError(error.RecordTooLarge, decode(allocator, &([_]u8{0} ** 301)));
    const tampered = try allocator.dupe(u8, bytes);
    defer allocator.free(tampered);
    tampered[5] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, decode(allocator, tampered));
}
