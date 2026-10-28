// Consensus gossip carries one SSZ value in a Snappy block. Req/resp streams
// instead prefix the uncompressed SSZ length and carry Snappy frames, so peers
// can reject oversized values before allocating. Frames have 64 KiB data
// limits and masked CRC32C checksums. A response code and fork context are
// outside this payload layer and must be checked by the protocol handler.
//
// gossip: SSZ -> Snappy block
// request/response payload: SSZ length -> Snappy stream header -> frames
// The pinned Phase 0 limit is 10 MiB of uncompressed data per payload.
const std = @import("std");
const snappy = @import("snappy.zig");

pub const max_payload_size: usize = 10 * 1024 * 1024;
const frame_size: usize = 65536;
const stream_identifier = [_]u8{ 0xff, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y' };

pub const Protocol = enum {
    status,
    ping,
    metadata,
    blocks_by_root,
    blocks_by_range,
    columns_by_root,
    columns_by_range,

    /// Return the exact negotiated protocol ID without its encoding suffix.
    pub fn id(self: Protocol) []const u8 {
        return switch (self) {
            .status => "/eth2/beacon_chain/req/status/2/",
            .ping => "/eth2/beacon_chain/req/ping/1/",
            .metadata => "/eth2/beacon_chain/req/metadata/3/",
            .blocks_by_root => "/eth2/beacon_chain/req/beacon_blocks_by_root/2/",
            .blocks_by_range => "/eth2/beacon_chain/req/beacon_blocks_by_range/2/",
            .columns_by_root => "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/",
            .columns_by_range => "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/",
        };
    }
};

pub const Topic = enum { block, attestation, aggregate_attestation, data_column };

/// Build a Fulu gossip topic, validating the subnet where one is required.
pub fn topicName(allocator: std.mem.Allocator, digest: [4]u8, kind: Topic, subnet: ?u8) ![]u8 {
    const hex = std.fmt.bytesToHex(digest, .lower);
    return switch (kind) {
        .block => if (subnet == null) std.fmt.allocPrint(allocator, "/eth2/{s}/beacon_block/ssz_snappy", .{&hex}) else error.InvalidSubnet,
        .aggregate_attestation => if (subnet == null) std.fmt.allocPrint(allocator, "/eth2/{s}/beacon_aggregate_and_proof/ssz_snappy", .{&hex}) else error.InvalidSubnet,
        .attestation => if (subnet) |index| if (index < 64) std.fmt.allocPrint(allocator, "/eth2/{s}/beacon_attestation_{d}/ssz_snappy", .{ &hex, index }) else error.InvalidSubnet else error.InvalidSubnet,
        .data_column => if (subnet) |index| if (index < 128) std.fmt.allocPrint(allocator, "/eth2/{s}/data_column_sidecar_{d}/ssz_snappy", .{ &hex, index }) else error.InvalidSubnet else error.InvalidSubnet,
    };
}

/// Encode one already serialized SSZ gossip payload as a Snappy block.
pub fn encodeGossip(allocator: std.mem.Allocator, ssz_bytes: []const u8, max_encoded: usize) ![]u8 {
    if (ssz_bytes.len > max_payload_size) return error.PayloadTooLarge;
    const encoded = try snappy.compress(allocator, ssz_bytes);
    errdefer allocator.free(encoded);
    if (encoded.len > max_encoded) return error.PayloadTooLarge;
    return encoded;
}

/// Decode bounded gossip bytes, checking the uncompressed size before allocation.
pub fn decodeGossip(allocator: std.mem.Allocator, encoded: []const u8, max_encoded: usize) ![]u8 {
    if (encoded.len > max_encoded) return error.PayloadTooLarge;
    return snappy.decompressLimited(allocator, encoded, max_payload_size);
}

/// Encode one SSZ request or response payload with a protobuf length and Snappy frames.
pub fn encodePayload(allocator: std.mem.Allocator, ssz_bytes: []const u8, type_max: usize) ![]u8 {
    if (ssz_bytes.len > @min(type_max, max_payload_size)) return error.PayloadTooLarge;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var length = ssz_bytes.len;
    while (length >= 128) : (length >>= 7) try output.append(allocator, @as(u8, @truncate(length)) | 0x80);
    try output.append(allocator, @intCast(length));
    try output.appendSlice(allocator, &stream_identifier);
    var offset: usize = 0;
    while (offset < ssz_bytes.len) {
        const data = ssz_bytes[offset..][0..@min(frame_size, ssz_bytes.len - offset)];
        const frame_len = data.len + 4;
        try output.appendSlice(allocator, &.{ 1, @truncate(frame_len), @truncate(frame_len >> 8), @truncate(frame_len >> 16) });
        var checksum: [4]u8 = undefined;
        std.mem.writeInt(u32, &checksum, maskedCrc(data), .little);
        try output.appendSlice(allocator, &checksum);
        try output.appendSlice(allocator, data);
        offset += data.len;
    }
    return output.toOwnedSlice(allocator);
}

/// Decode one complete SSZ payload, rejecting size, length, frame, and checksum errors.
pub fn decodePayload(allocator: std.mem.Allocator, encoded: []const u8, type_max: usize) ![]u8 {
    var cursor: usize = 0;
    const expected = try readLength(encoded, &cursor);
    if (expected > @min(type_max, max_payload_size)) return error.PayloadTooLarge;
    const max_encoded = expected + expected / 6 + 32 + 8 * ((expected + frame_size - 1) / frame_size);
    if (encoded.len > max_encoded + 20) return error.PayloadTooLarge;
    if (encoded.len - cursor < stream_identifier.len or
        !std.mem.eql(u8, encoded[cursor..][0..stream_identifier.len], &stream_identifier)) return error.InvalidFrame;
    cursor += stream_identifier.len;
    const output = try allocator.alloc(u8, expected);
    errdefer allocator.free(output);
    var written: usize = 0;
    while (cursor < encoded.len) {
        if (written == expected or encoded.len - cursor < 4) return error.InvalidFrame;
        const kind = encoded[cursor];
        const chunk_len = @as(usize, encoded[cursor + 1]) | (@as(usize, encoded[cursor + 2]) << 8) | (@as(usize, encoded[cursor + 3]) << 16);
        cursor += 4;
        if (chunk_len > encoded.len - cursor) return error.InvalidFrame;
        const chunk = encoded[cursor..][0..chunk_len];
        cursor += chunk_len;
        if (kind >= 0x80 and kind <= 0xfe) continue;
        if (kind == 0xff) {
            if (!std.mem.eql(u8, chunk, stream_identifier[4..])) return error.InvalidFrame;
            continue;
        }
        if (kind != 0 and kind != 1 or chunk.len < 4) return error.InvalidFrame;
        const checksum = std.mem.readInt(u32, chunk[0..4], .little);
        const data = if (kind == 0) try snappy.decompressLimited(allocator, chunk[4..], frame_size) else null;
        defer if (data) |owned| allocator.free(owned);
        const plain = data orelse chunk[4..];
        if (plain.len > frame_size or plain.len > expected - written) return error.InvalidFrame;
        if (checksum != maskedCrc(plain)) return error.InvalidChecksum;
        @memcpy(output[written..][0..plain.len], plain);
        written += plain.len;
    }
    if (written != expected) return error.InvalidLength;
    return output;
}

/// Read a full-range protobuf unsigned varint before any payload allocation.
fn readLength(input: []const u8, cursor: *usize) !usize {
    var value: u64 = 0;
    for (0..10) |i| {
        if (cursor.* >= input.len) return error.InvalidLength;
        const byte = input[cursor.*];
        cursor.* += 1;
        if (i == 9 and byte > 1) return error.InvalidLength;
        value |= @as(u64, byte & 0x7f) << @intCast(i * 7);
        if (byte & 0x80 == 0) {
            if (i > 0 and byte == 0) return error.InvalidLength;
            return std.math.cast(usize, value) orelse error.PayloadTooLarge;
        }
    }
    return error.InvalidLength;
}

/// Mask the Castagnoli CRC used by each Snappy frame.
fn maskedCrc(data: []const u8) u32 {
    const crc = std.hash.crc.Crc32Iscsi.hash(data);
    return ((crc >> 15) | (crc << 17)) +% 0xa282ead8;
}

test "gossip and framed payload round trips enforce bounds" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(u32, 0xc78ab0e5), maskedCrc("123456789"));
    const input = try allocator.alloc(u8, frame_size + 1);
    defer allocator.free(input);
    @memset(input, 0x42);
    const gossip = try encodeGossip(allocator, input, input.len + 32);
    defer allocator.free(gossip);
    const decoded_gossip = try decodeGossip(allocator, gossip, gossip.len);
    defer allocator.free(decoded_gossip);
    try std.testing.expectEqualSlices(u8, input, decoded_gossip);
    try std.testing.expectError(error.PayloadTooLarge, decodeGossip(allocator, gossip, gossip.len - 1));

    const framed = try encodePayload(allocator, input, input.len);
    defer allocator.free(framed);
    const decoded = try decodePayload(allocator, framed, input.len);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, input, decoded);
    try std.testing.expectError(error.PayloadTooLarge, decodePayload(allocator, framed, input.len - 1));
    var corrupt = try allocator.dupe(u8, framed);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidChecksum, decodePayload(allocator, corrupt, input.len));
    try std.testing.expectError(error.InvalidLength, decodePayload(allocator, &.{ 0x80, 0x00 }, 100));
    try std.testing.expectError(error.PayloadTooLarge, decodePayload(allocator, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 }, max_payload_size));
}

test "framed decoder accepts compressed chunks and rejects trailing data" {
    const allocator = std.testing.allocator;
    const raw = [_]u8{ 3, 8, 'a', 'b', 'c' };
    var frame = [_]u8{ 3, 0xff, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y', 0, 9, 0, 0, 0, 0, 0, 0, 3, 8, 'a', 'b', 'c' };
    std.mem.writeInt(u32, frame[15..19], maskedCrc("abc"), .little);
    const decoded = try decodePayload(allocator, &frame, 3);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("abc", decoded);
    try std.testing.expectEqualSlices(u8, &raw, frame[19..]);
    const extra = try allocator.dupe(u8, &frame);
    defer allocator.free(extra);
    extra[0] = 4;
    try std.testing.expectError(error.InvalidLength, decodePayload(allocator, extra, 4));
}

test "Fulu protocol IDs and gossip topic names use exact fork digest and bounds" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqualStrings("/eth2/beacon_chain/req/status/2/", Protocol.status.id());
    try std.testing.expectEqualStrings("/eth2/beacon_chain/req/data_column_sidecars_by_root/1/", Protocol.columns_by_root.id());
    const digest = [_]u8{ 0x12, 0x34, 0xab, 0xcd };
    const block = try topicName(allocator, digest, .block, null);
    defer allocator.free(block);
    try std.testing.expectEqualStrings("/eth2/1234abcd/beacon_block/ssz_snappy", block);
    const column = try topicName(allocator, digest, .data_column, 127);
    defer allocator.free(column);
    try std.testing.expectEqualStrings("/eth2/1234abcd/data_column_sidecar_127/ssz_snappy", column);
    try std.testing.expectError(error.InvalidSubnet, topicName(allocator, digest, .data_column, 128));
    try std.testing.expectError(error.InvalidSubnet, topicName(allocator, digest, .attestation, 64));
}
