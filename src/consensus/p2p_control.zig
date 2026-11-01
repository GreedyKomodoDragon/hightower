// Status is the first Req/Resp exchange after a peer connection: it carries
// the current fork digest, finalized and head checkpoints, and the earliest
// slot the peer can serve. Ping exchanges metadata sequence numbers, while
// MetaData advertises subnet interests and the Fulu custody promise. Check
// fixed SSZ lengths before accepting these untrusted control messages.
//
//   authenticated stream -> bounded Snappy -> exact SSZ -> fork/custody gate
// Status v2 is 92 bytes, Ping v1 is 8, and MetaData v3 is 25.
const std = @import("std");
const fulu = @import("fulu");
const types = @import("types");
const ssz = @import("ssz");
const columns = @import("data_columns.zig");
const wire = @import("p2p_wire.zig");

const status_size: usize = 92;
const ping_size: usize = 8;
const metadata_size: usize = 25;

pub const Status = struct {
    fork_digest: [4]u8,
    finalized_root: fulu.Root,
    finalized_epoch: fulu.Epoch,
    head_root: fulu.Root,
    head_slot: fulu.Slot,
    earliest_available_slot: fulu.Slot,
};

pub const MetaData = struct {
    seq_number: u64,
    attnets: types.BitVector(64),
    syncnets: types.BitVector(4),
    custody_group_count: u64,
};

/// Encode a Fulu Status v2 request payload; the caller frees it.
pub fn encodeStatus(allocator: std.mem.Allocator, value: Status) ![]u8 {
    return encodeValue(allocator, value, status_size);
}

/// Decode exactly one Fulu Status v2 payload before checking peer compatibility.
pub fn decodeStatus(allocator: std.mem.Allocator, encoded: []const u8) !Status {
    return decodeValue(Status, allocator, encoded, status_size);
}

/// Encode one successful Status v2 response chunk for the negotiated stream.
pub fn encodeStatusResponse(allocator: std.mem.Allocator, value: Status) ![]u8 {
    return encodeResponse(allocator, .status, value, status_size);
}

/// Decode a successful Status v2 chunk after stream framing has been checked.
pub fn decodeStatusResponse(allocator: std.mem.Allocator, chunk: *const wire.ResponseChunk) !Status {
    return decodeResponse(Status, allocator, chunk, status_size);
}

/// Require the peer's advertised fork to match the current local fork digest.
pub fn checkStatus(value: Status, expected_digest: [4]u8) !void {
    if (!std.mem.eql(u8, &value.fork_digest, &expected_digest)) return error.InvalidForkContext;
}

/// Encode the local metadata sequence number as a Ping v1 payload.
pub fn encodePing(allocator: std.mem.Allocator, seq_number: u64) ![]u8 {
    return encodeValue(allocator, seq_number, ping_size);
}

/// Decode a Ping v1 sequence number, rejecting non-exact SSZ lengths.
pub fn decodePing(allocator: std.mem.Allocator, encoded: []const u8) !u64 {
    return decodeValue(u64, allocator, encoded, ping_size);
}

/// Encode one successful Ping v1 response chunk.
pub fn encodePingResponse(allocator: std.mem.Allocator, seq_number: u64) ![]u8 {
    return encodeResponse(allocator, .ping, seq_number, ping_size);
}

/// Decode a successful Ping v1 response chunk.
pub fn decodePingResponse(allocator: std.mem.Allocator, chunk: *const wire.ResponseChunk) !u64 {
    return decodeResponse(u64, allocator, chunk, ping_size);
}

/// Encode Metadata v3 after checking the advertised custody count.
pub fn encodeMetadata(allocator: std.mem.Allocator, value: MetaData) ![]u8 {
    try checkCustody(value.custody_group_count);
    return encodeValue(allocator, value, metadata_size);
}

/// Decode Metadata v3 and reject impossible Fulu custody promises.
pub fn decodeMetadata(allocator: std.mem.Allocator, encoded: []const u8) !MetaData {
    const value = try decodeValue(MetaData, allocator, encoded, metadata_size);
    try checkCustody(value.custody_group_count);
    return value;
}

/// Encode one successful Metadata v3 response chunk after custody validation.
pub fn encodeMetadataResponse(allocator: std.mem.Allocator, value: MetaData) ![]u8 {
    try checkCustody(value.custody_group_count);
    return encodeResponse(allocator, .metadata, value, metadata_size);
}

/// Decode a successful Metadata v3 response chunk and its custody count.
pub fn decodeMetadataResponse(allocator: std.mem.Allocator, chunk: *const wire.ResponseChunk) !MetaData {
    const value = try decodeResponse(MetaData, allocator, chunk, metadata_size);
    try checkCustody(value.custody_group_count);
    return value;
}

/// Accept only the configured Fulu custody range shared with ENR validation.
fn checkCustody(count: u64) !void {
    if (count < columns.custody_requirement or count > columns.column_count) return error.InvalidCustodyCount;
}

/// Serialize one fixed-size SSZ value in bounded Req/Resp framing.
fn encodeValue(allocator: std.mem.Allocator, value: anytype, expected_size: usize) ![]u8 {
    const bytes = try serializeValue(allocator, value, expected_size);
    defer allocator.free(bytes);
    return wire.encodePayload(allocator, bytes, expected_size);
}

/// Serialize one fixed-size SSZ value, returning bytes owned by the caller.
fn serializeValue(allocator: std.mem.Allocator, value: anytype, expected_size: usize) ![]u8 {
    const bytes = try ssz.serializeAlloc(allocator, value);
    if (bytes.len != expected_size) {
        allocator.free(bytes);
        return error.InvalidLength;
    }
    return bytes;
}

/// Wrap one fixed-size SSZ value as a successful Req/Resp response chunk.
fn encodeResponse(allocator: std.mem.Allocator, protocol: wire.Protocol, value: anytype, expected_size: usize) ![]u8 {
    const bytes = try serializeValue(allocator, value, expected_size);
    defer allocator.free(bytes);
    return wire.encodeResponseChunk(allocator, protocol, .success, null, bytes, expected_size);
}

/// Decode one fixed-size SSZ value from its complete Snappy payload.
fn decodeValue(comptime T: type, allocator: std.mem.Allocator, encoded: []const u8, expected_size: usize) !T {
    const bytes = try wire.decodePayload(allocator, encoded, expected_size);
    defer allocator.free(bytes);
    return decodeSsz(T, allocator, bytes, expected_size);
}

/// Decode fixed-size SSZ from a response payload after its chunk is framed.
fn decodeResponse(comptime T: type, allocator: std.mem.Allocator, chunk: *const wire.ResponseChunk, expected_size: usize) !T {
    if (chunk.code != .success or chunk.fork_digest != null) return error.InvalidResponseCode;
    return decodeSsz(T, allocator, chunk.payload, expected_size);
}

/// Require an exact SSZ byte count before deserializing a control value.
fn decodeSsz(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8, expected_size: usize) !T {
    if (bytes.len != expected_size) return error.InvalidLength;
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, T, &reader);
}

test "Fulu Status v2 checks exact SSZ and fork context" {
    const allocator = std.testing.allocator;
    const status = Status{
        .fork_digest = .{ 1, 2, 3, 4 },
        .finalized_root = [_]u8{5} ** 32,
        .finalized_epoch = 2,
        .head_root = [_]u8{6} ** 32,
        .head_slot = 64,
        .earliest_available_slot = 32,
    };
    const encoded = try encodeStatus(allocator, status);
    defer allocator.free(encoded);
    const decoded = try decodeStatus(allocator, encoded);
    try std.testing.expectEqualDeep(status, decoded);
    try checkStatus(decoded, status.fork_digest);
    try std.testing.expectError(error.InvalidForkContext, checkStatus(decoded, .{ 1, 2, 3, 5 }));
    const response = try encodeStatusResponse(allocator, status);
    defer allocator.free(response);
    const chunk = try wire.decodeResponseChunk(allocator, .status, response, null, status_size);
    defer allocator.free(chunk.payload);
    try std.testing.expectEqualDeep(status, try decodeStatusResponse(allocator, &chunk));
    try std.testing.expectError(error.InvalidResponseCode, decodeStatusResponse(allocator, &.{ .code = .server_error, .fork_digest = null, .payload = &.{} }));
    const short = try wire.encodePayload(allocator, &([_]u8{0} ** (status_size - 1)), status_size);
    defer allocator.free(short);
    try std.testing.expectError(error.InvalidLength, decodeStatus(allocator, short));
    try std.testing.expectError(error.InvalidFrame, decodeStatus(allocator, &.{ 0, 1, 2 }));
}

test "Ping v1 and Metadata v3 use bounded exact SSZ payloads" {
    const allocator = std.testing.allocator;
    const ping = try encodePing(allocator, 0x0102030405060708);
    defer allocator.free(ping);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), try decodePing(allocator, ping));
    const ping_response = try encodePingResponse(allocator, 9);
    defer allocator.free(ping_response);
    const ping_chunk = try wire.decodeResponseChunk(allocator, .ping, ping_response, null, ping_size);
    defer allocator.free(ping_chunk.payload);
    try std.testing.expectEqual(@as(u64, 9), try decodePingResponse(allocator, &ping_chunk));
    const bad_ping = try wire.encodePayload(allocator, &([_]u8{0} ** (ping_size + 1)), ping_size + 1);
    defer allocator.free(bad_ping);
    try std.testing.expectError(error.PayloadTooLarge, decodePing(allocator, bad_ping));

    var attnets = [_]bool{false} ** 64;
    attnets[3] = true;
    var syncnets = [_]bool{false} ** 4;
    syncnets[1] = true;
    const metadata = MetaData{ .seq_number = 7, .attnets = .{ .data = attnets }, .syncnets = .{ .data = syncnets }, .custody_group_count = columns.custody_requirement };
    const encoded = try encodeMetadata(allocator, metadata);
    defer allocator.free(encoded);
    try std.testing.expectEqualDeep(metadata, try decodeMetadata(allocator, encoded));
    const response = try encodeMetadataResponse(allocator, metadata);
    defer allocator.free(response);
    const chunk = try wire.decodeResponseChunk(allocator, .metadata, response, null, metadata_size);
    defer allocator.free(chunk.payload);
    try std.testing.expectEqualDeep(metadata, try decodeMetadataResponse(allocator, &chunk));
    const plain = try wire.decodePayload(allocator, encoded, metadata_size);
    defer allocator.free(plain);
    try std.testing.expectEqual(@as(usize, metadata_size), plain.len);
    try std.testing.expectEqual(@as(u64, 7), std.mem.readInt(u64, plain[0..8], .little));
    try std.testing.expectEqual(@as(u8, 1 << 3), plain[8]);
    try std.testing.expectEqual(@as(u8, 1 << 1), plain[16]);
    try std.testing.expectEqual(@as(u64, columns.custody_requirement), std.mem.readInt(u64, plain[17..25], .little));
    var invalid = metadata;
    invalid.custody_group_count = columns.custody_requirement - 1;
    try std.testing.expectError(error.InvalidCustodyCount, encodeMetadata(allocator, invalid));
    invalid.custody_group_count = columns.column_count + 1;
    const invalid_bytes = try ssz.serializeAlloc(allocator, invalid);
    defer allocator.free(invalid_bytes);
    const invalid_wire = try wire.encodePayload(allocator, invalid_bytes, metadata_size);
    defer allocator.free(invalid_wire);
    try std.testing.expectError(error.InvalidCustodyCount, decodeMetadata(allocator, invalid_wire));
}
