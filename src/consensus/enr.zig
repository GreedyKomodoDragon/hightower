// Ethereum Node Records bind a discovery identity and endpoint to one
// secp256k1 signature. Fulu records promise a fork and custody count;
// execution records carry an EIP-2124 fork ID. Peers verify the signature
// and the relevant fork policy before using an address. Records are capped at
// 300 encoded bytes with sorted, unique keys.
//
//   RLP record -> verify signature -> fork/custody gate -> discovery candidate
const std = @import("std");
const rlp = @import("rlp");
const columns = @import("data_columns.zig");
const fork_id = @import("execution").fork_id;

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Scalar = std.crypto.ecc.Secp256k1.scalar;
const Keccak = std.crypto.hash.sha3.Keccak256;
const Field = enum { cgc, eth, eth2, id, ip, nfd, secp256k1, tcp, udp, unknown };
pub const Policy = union(enum) { consensus: [4]u8, execution: struct { schedule: fork_id.Schedule, block: u64, timestamp: u64 } };

pub const Local = struct {
    sequence: u64,
    ip: [4]u8,
    udp_port: u16,
    tcp_port: u16,
    fork_id: [16]u8,
    next_fork_digest: [4]u8,
    custody_group_count: u64,
    execution_fork: ?fork_id.Id = null,
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
    execution_fork: ?fork_id.Id = null,
};

/// Encode a signed IPv4 Fulu or execution ENR; the caller owns the bytes.
pub fn encode(allocator: std.mem.Allocator, key_pair: Ecdsa.KeyPair, record: Local) ![]u8 {
    if (record.execution_fork == null and (record.custody_group_count < columns.custody_requirement or record.custody_group_count > columns.column_count)) return error.InvalidCustodyCount;
    if (record.udp_port == 0 or record.tcp_port == 0) return error.InvalidEndpoint;
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    try writeInt(&payload.writer, record.sequence);
    // ENR cgc is minimal big-endian; SSZ's fixed little-endian uint64 does not apply here.
    if (record.execution_fork) |id| {
        var nested = std.Io.Writer.Allocating.init(allocator);
        defer nested.deinit();
        try rlp.encoding.encodeString(&nested.writer, &id.hash);
        try writeInt(&nested.writer, id.next);
        const pair = try wrapList(allocator, nested.written());
        defer allocator.free(pair);
        var entry = std.Io.Writer.Allocating.init(allocator);
        defer entry.deinit();
        try rlp.encoding.encodeListHeader(&entry.writer, pair.len);
        try entry.writer.writeAll(pair);
        try rlp.encoding.encodeString(&payload.writer, "eth");
        try payload.writer.writeAll(entry.written());
    } else {
        try writePair(&payload.writer, "cgc", record.custody_group_count);
        try writePair(&payload.writer, "eth2", &record.fork_id);
    }
    try writePair(&payload.writer, "id", "v4");
    try writePair(&payload.writer, "ip", &record.ip);
    if (record.execution_fork == null) try writePair(&payload.writer, "nfd", &record.next_fork_digest);
    const public_key = key_pair.public_key.toCompressedSec1();
    try writePair(&payload.writer, "secp256k1", &public_key);
    try writePair(&payload.writer, "tcp", record.tcp_port);
    try writePair(&payload.writer, "udp", record.udp_port);
    const content = try wrapList(allocator, payload.written());
    defer allocator.free(content);
    var digest: [32]u8 = undefined;
    Keccak.hash(content, &digest, .{});
    var signed_digest = try key_pair.signPrehashed(digest, null);
    if (std.mem.readInt(u256, &signed_digest.s, .big) > Scalar.field_order / 2) {
        signed_digest.s = try Scalar.neg(signed_digest.s, .big);
    }
    const signature = signed_digest.toBytes();
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
    return decodeWithPolicy(allocator, bytes, .consensus);
}

/// Authenticate a standard execution ENR or a Fulu consensus ENR.
pub fn decodeWithPolicy(allocator: std.mem.Allocator, bytes: []const u8, kind: enum { consensus, execution }) !Record {
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
    // Missing policy fields stay zero until the required-field check below.
    var record: Record = std.mem.zeroes(Record);
    record.sequence = try integer(u64, try string(items[1]));
    var seen: u16 = 0;
    var prior: []const u8 = "";
    for (1..items.len / 2) |pair_index| {
        const key = try string(items[pair_index * 2]);
        const data_item = items[pair_index * 2 + 1];
        const data = if (data_item == .string) data_item.string else &.{};
        if (key.len == 0 or (pair_index > 1 and std.mem.order(u8, prior, key) != .lt)) return error.InvalidRecord;
        prior = key;
        switch (std.meta.stringToEnum(Field, key) orelse .unknown) {
            .cgc => {
                record.custody_group_count = try integer(u64, data);
                seen |= 1;
            },
            .eth => {
                if (data_item != .list or data_item.list.len == 0 or data_item.list[0] != .list or data_item.list[0].list.len != 2) return error.InvalidForkContext;
                const fields = data_item.list[0].list;
                const hash = try string(fields[0]);
                if (hash.len != 4) return error.InvalidForkContext;
                record.execution_fork = .{ .hash = hash[0..4].*, .next = try integer(u64, try string(fields[1])) };
                seen |= 256;
            },
            .eth2 => {
                if (data.len != 16) return error.InvalidForkContext;
                record.fork_id = data[0..16].*;
                seen |= 2;
            },
            .id => {
                if (!std.mem.eql(u8, data, "v4")) return error.InvalidIdentity;
                seen |= 4;
            },
            .ip => {
                if (data.len != 4) return error.InvalidEndpoint;
                record.ip = data[0..4].*;
                seen |= 8;
            },
            .nfd => {
                if (data.len != 4) return error.InvalidForkContext;
                record.next_fork_digest = data[0..4].*;
                seen |= 16;
            },
            .secp256k1 => {
                if (data.len != 33) return error.InvalidIdentity;
                record.public_key = data[0..33].*;
                seen |= 32;
            },
            .tcp => {
                record.tcp_port = try integer(u16, data);
                seen |= 64;
            },
            .udp => {
                record.udp_port = try integer(u16, data);
                seen |= 128;
            },
            .unknown => {},
        }
    }
    const common: u16 = 4 | 8 | 32 | 64 | 128;
    if ((seen & common) != common or record.udp_port == 0 or record.tcp_port == 0) return error.InvalidRecord;
    if (kind == .consensus and ((seen & 19) != 19 or record.custody_group_count < columns.custody_requirement or record.custody_group_count > columns.column_count)) return error.InvalidRecord;
    if (kind == .execution and record.execution_fork == null) return error.InvalidRecord;
    const public_key = try Ecdsa.PublicKey.fromSec1(&record.public_key);
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    for (items) |item| try writeValue(allocator, &payload.writer, item);
    const canonical = try wrapList(allocator, payload.written());
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical)) return error.InvalidRecord;
    var signed_payload = std.Io.Writer.Allocating.init(allocator);
    defer signed_payload.deinit();
    for (items[1..]) |item| try writeValue(allocator, &signed_payload.writer, item);
    const content = try wrapList(allocator, signed_payload.written());
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

/// Check a signed ENR against its network's discovery policy.
pub fn requirePolicy(record: Record, policy: Policy) !void {
    switch (policy) {
        .consensus => |digest| try requireFork(record, digest),
        .execution => |context| {
            const remote = record.execution_fork orelse return error.InvalidForkContext;
            if (!context.schedule.compatible(context.block, context.timestamp, remote)) return error.InvalidForkContext;
        },
    }
}

/// Keep execution discovery within the local endpoint's routing scope.
pub fn safeExecutionEndpoint(local: [4]u8, remote: [4]u8) bool {
    if (remote[0] == 0 or remote[0] >= 224 or remote[0] == 169 and remote[1] == 254 or remote[0] == 100 and remote[1] >= 64 and remote[1] < 128) return false;
    if (remote[0] == 192 and remote[1] == 0 and (remote[2] == 0 or remote[2] == 2)) return false;
    if (remote[0] == 198 and (remote[1] == 18 or remote[1] == 19 or remote[1] == 51 and remote[2] == 100)) return false;
    if (remote[0] == 203 and remote[1] == 0 and remote[2] == 113) return false;
    if (remote[0] == 127) return local[0] == 127 and remote[1] == 0 and remote[2] == 0 and remote[3] != 0;
    const private_remote = remote[0] == 10 or remote[0] == 172 and remote[1] >= 16 and remote[1] <= 31 or remote[0] == 192 and remote[1] == 168;
    if (!private_remote) return true;
    return remote[0] == local[0] and remote[1] == local[1] and remote[2] == local[2];
}

/// Return the byte string in an RLP item.
fn string(value: rlp.decode.Value) ![]const u8 {
    return switch (value) {
        .string => |bytes| bytes,
        else => error.InvalidRecord,
    };
}

/// Serialize nested ENR entry values for canonical and signature checks.
fn writeValue(allocator: std.mem.Allocator, writer: *std.Io.Writer, value: rlp.decode.Value) !void {
    switch (value) {
        .string => |data| return rlp.encoding.encodeString(writer, data),
        .list => |items| {
            var nested = std.Io.Writer.Allocating.init(allocator);
            defer nested.deinit();
            for (items) |item| try writeValue(allocator, &nested.writer, item);
            try rlp.encoding.encodeListHeader(writer, nested.written().len);
            return writer.writeAll(nested.written());
        },
    }
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
        return writeInt(writer, value);
    }
    return rlp.encoding.encodeString(writer, value);
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
    var invalid_endpoint = record;
    invalid_endpoint.tcp_port = 0;
    try std.testing.expectError(error.InvalidEndpoint, encode(allocator, key_pair, invalid_endpoint));
    try std.testing.expectError(error.RecordTooLarge, decode(allocator, &([_]u8{0} ** 301)));
    const tampered = try allocator.dupe(u8, bytes);
    defer allocator.free(tampered);
    tampered[5] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, decode(allocator, tampered));

    var decoded = try rlp.decode.decodeAll(allocator, bytes);
    defer decoded.deinit(allocator);
    const items = decoded.list;
    try std.testing.expectEqualSlices(u8, &.{columns.custody_requirement}, try string(items[3]));
    var malformed_payload = std.Io.Writer.Allocating.init(allocator);
    defer malformed_payload.deinit();
    try rlp.encoding.encodeString(&malformed_payload.writer, try string(items[0]));
    try malformed_payload.writer.writeAll(&.{ 0x81, 0x01 }); // non-canonical sequence 1
    for (items[2..]) |item| try rlp.encoding.encodeString(&malformed_payload.writer, try string(item));
    const malformed = try wrapList(allocator, malformed_payload.written());
    defer allocator.free(malformed);
    try std.testing.expectError(error.InvalidRecord, decode(allocator, malformed));
}

test "all locally signed ENRs use low-S signatures accepted by external secp256k1 verifiers" {
    const allocator = std.testing.allocator;
    const local = Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 9000, .tcp_port = 9001, .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = columns.custody_requirement };
    for (1..17) |value| {
        const key = try Ecdsa.KeyPair.generateDeterministic([_]u8{@intCast(value)} ** 32);
        const bytes = try encode(allocator, key, local);
        defer allocator.free(bytes);
        var decoded = try rlp.decode.decodeAll(allocator, bytes);
        defer decoded.deinit(allocator);
        const signature = try string(decoded.list[0]);
        try std.testing.expect(std.mem.readInt(u256, signature[32..64], .big) <= Scalar.field_order / 2);
        _ = try decode(allocator, bytes);
    }
}

test "execution ENR verifies its signed eth fork entry without consensus fields" {
    const allocator = std.testing.allocator;
    const key = try Ecdsa.KeyPair.generateDeterministic([_]u8{81} ** 32);
    const schedule = fork_id.Schedule{ .genesis = .{3} ** 32, .genesis_time = 0 };
    const local = Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 30303, .tcp_port = 30303, .fork_id = .{0} ** 16, .next_fork_digest = .{0} ** 4, .custody_group_count = 0, .execution_fork = schedule.at(0, 0) };
    const bytes = try encode(allocator, key, local);
    defer allocator.free(bytes);
    const record = try decodeWithPolicy(allocator, bytes, .execution);
    try requirePolicy(record, .{ .execution = .{ .schedule = schedule, .block = 0, .timestamp = 0 } });
    try std.testing.expectError(error.InvalidRecord, decode(allocator, bytes));
    var other = schedule;
    other.genesis = .{4} ** 32;
    try std.testing.expectError(error.InvalidForkContext, requirePolicy(record, .{ .execution = .{ .schedule = other, .block = 0, .timestamp = 0 } }));
    const tampered = try allocator.dupe(u8, bytes);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, decodeWithPolicy(allocator, tampered, .execution));
    try std.testing.expect(!safeExecutionEndpoint(.{ 8, 8, 8, 8 }, .{ 127, 0, 0, 1 }));
}
