// Discv5 masks packet headers with AES-CTR using the destination node ID.
// A WHOAREYOU challenge echoes the triggering nonce and carries a fresh ID
// nonce and the requester's ENR sequence. Header inspection only identifies
// the packet shape; it does not authenticate ordinary message contents.
//
//   masking IV + masked header -> packet kind -> challenge/session handling
// Datagram size is 63..1280 bytes. Session and handshake processing is separate.
const std = @import("std");

pub const max_packet_size: usize = 1280;
pub const min_packet_size: usize = 63;
const static_header_size: usize = 23;
const iv_size: usize = 16;
const challenge_auth_size: usize = 24;
const ordinary_auth_size: usize = 32;
const gcm_tag_size: usize = 16;
const ordinary_overhead: usize = iv_size + static_header_size + ordinary_auth_size + gcm_tag_size;
const AesGcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const Kind = enum(u8) { ordinary = 0, whoareyou = 1, handshake = 2 };
pub const Header = struct { kind: Kind, nonce: [12]u8, authdata_size: u16 };
pub const Challenge = struct { request_nonce: [12]u8, id_nonce: [16]u8, enr_sequence: u64 };
pub const Ordinary = struct {
    source_id: [32]u8,
    nonce: [12]u8,
    plaintext: []u8,

    /// Release the authenticated plaintext returned by decodeOrdinary.
    pub fn deinit(self: Ordinary, allocator: std.mem.Allocator) void {
        allocator.free(self.plaintext);
    }
};

/// Encrypt one ordinary packet with a handshake-derived directional session key.
/// The caller must provide a nonce unique within that key's lifetime.
pub fn encodeOrdinary(allocator: std.mem.Allocator, destination_id: [32]u8, source_id: [32]u8, masking_iv: [16]u8, nonce: [12]u8, session_key: [16]u8, plaintext: []const u8) ![]u8 {
    if (plaintext.len == 0 or plaintext.len > max_packet_size - ordinary_overhead) return error.InvalidMessageSize;
    var header: [static_header_size + ordinary_auth_size]u8 = undefined;
    @memcpy(header[0..6], "discv5");
    std.mem.writeInt(u16, header[6..8], 1, .big);
    header[8] = @intFromEnum(Kind.ordinary);
    @memcpy(header[9..21], &nonce);
    std.mem.writeInt(u16, header[21..23], ordinary_auth_size, .big);
    @memcpy(header[23..55], &source_id);
    var packet = try allocator.alloc(u8, ordinary_overhead + plaintext.len);
    errdefer allocator.free(packet);
    @memcpy(packet[0..iv_size], &masking_iv);
    mask(destination_id, masking_iv, packet[iv_size .. iv_size + header.len], &header);
    var associated_data: [iv_size + header.len]u8 = undefined;
    @memcpy(associated_data[0..iv_size], &masking_iv);
    @memcpy(associated_data[iv_size..], &header);
    AesGcm.encrypt(packet[iv_size + header.len .. packet.len - gcm_tag_size], packet[packet.len - gcm_tag_size ..][0..gcm_tag_size], plaintext, &associated_data, nonce, session_key);
    return packet;
}

/// Authenticate and decrypt an ordinary packet before exposing its source or plaintext.
/// The caller must reject replayed nonces for each peer and session key.
pub fn decodeOrdinary(allocator: std.mem.Allocator, destination_id: [32]u8, session_key: [16]u8, packet: []const u8) !Ordinary {
    const summary = try inspect(destination_id, packet);
    if (summary.kind != .ordinary or packet.len <= ordinary_overhead) return error.InvalidPacketHeader;
    var header: [static_header_size + ordinary_auth_size]u8 = undefined;
    mask(destination_id, packet[0..iv_size].*, &header, packet[iv_size .. iv_size + header.len]);
    var associated_data: [iv_size + header.len]u8 = undefined;
    @memcpy(associated_data[0..iv_size], packet[0..iv_size]);
    @memcpy(associated_data[iv_size..], &header);
    const ciphertext = packet[iv_size + header.len .. packet.len - gcm_tag_size];
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);
    try AesGcm.decrypt(plaintext, ciphertext, packet[packet.len - gcm_tag_size ..][0..gcm_tag_size].*, &associated_data, summary.nonce, session_key);
    return .{ .source_id = header[23..55].*, .nonce = summary.nonce, .plaintext = plaintext };
}

/// Mask a complete WHOAREYOU challenge for the destination discovery node ID.
pub fn encodeWhoAreYou(destination_id: [32]u8, masking_iv: [16]u8, challenge: Challenge) [63]u8 {
    var packet: [63]u8 = undefined;
    @memcpy(packet[0..iv_size], &masking_iv);
    var header: [static_header_size + challenge_auth_size]u8 = undefined;
    @memcpy(header[0..6], "discv5");
    std.mem.writeInt(u16, header[6..8], 1, .big);
    header[8] = @intFromEnum(Kind.whoareyou);
    @memcpy(header[9..21], &challenge.request_nonce);
    std.mem.writeInt(u16, header[21..23], challenge_auth_size, .big);
    @memcpy(header[23..39], &challenge.id_nonce);
    std.mem.writeInt(u64, header[39..47], challenge.enr_sequence, .big);
    mask(destination_id, masking_iv, packet[16..], &header);
    return packet;
}

/// Inspect a bounded packet header without trusting its unauthenticated contents.
pub fn inspect(destination_id: [32]u8, packet: []const u8) !Header {
    if (packet.len < min_packet_size or packet.len > max_packet_size) return error.InvalidPacketSize;
    var header: [static_header_size]u8 = undefined;
    mask(destination_id, packet[0..16].*, &header, packet[16..39]);
    if (!std.mem.eql(u8, header[0..6], "discv5") or std.mem.readInt(u16, header[6..8], .big) != 1) return error.InvalidPacketHeader;
    const kind: Kind = switch (header[8]) {
        0 => .ordinary,
        1 => .whoareyou,
        2 => .handshake,
        else => return error.InvalidPacketHeader,
    };
    const authdata_size = std.mem.readInt(u16, header[21..23], .big);
    if (authdata_size > packet.len - iv_size - static_header_size) return error.InvalidPacketHeader;
    switch (kind) {
        .whoareyou => if (authdata_size != challenge_auth_size or packet.len != min_packet_size) return error.InvalidPacketHeader,
        .ordinary => if (authdata_size != 32 or packet.len < iv_size + static_header_size + 32 + 16) return error.InvalidPacketHeader,
        .handshake => if (authdata_size < 34 or packet.len < iv_size + static_header_size + authdata_size + 16) return error.InvalidPacketHeader,
    }
    return .{ .kind = kind, .nonce = header[9..21].*, .authdata_size = authdata_size };
}

/// Unmask and validate a WHOAREYOU challenge addressed to this node.
pub fn decodeWhoAreYou(destination_id: [32]u8, packet: []const u8) !Challenge {
    const header = try inspect(destination_id, packet);
    if (header.kind != .whoareyou) return error.InvalidPacketHeader;
    var plain: [static_header_size + challenge_auth_size]u8 = undefined;
    mask(destination_id, packet[0..16].*, &plain, packet[16..63]);
    return .{ .request_nonce = header.nonce, .id_nonce = plain[23..39].*, .enr_sequence = std.mem.readInt(u64, plain[39..47], .big) };
}

/// Return the exact unmasked WHOAREYOU bytes signed and used as the HKDF salt.
pub fn challengeData(destination_id: [32]u8, packet: []const u8) ![63]u8 {
    const header = try inspect(destination_id, packet);
    if (header.kind != .whoareyou) return error.InvalidPacketHeader;
    var data: [63]u8 = undefined;
    @memcpy(data[0..iv_size], packet[0..iv_size]);
    mask(destination_id, packet[0..iv_size].*, data[iv_size..], packet[iv_size..]);
    return data;
}

/// XOR packet header bytes with the destination-keyed AES-CTR stream.
fn mask(destination_id: [32]u8, iv: [16]u8, output: []u8, input: []const u8) void {
    const aes = std.crypto.core.aes.Aes128.initEnc(destination_id[0..16].*);
    std.crypto.core.modes.ctr(@TypeOf(aes), aes, output, input, iv, .big);
}

test "WHOAREYOU header masking matches the packet shape and rejects wrong destination" {
    const destination_id = [_]u8{0x11} ** 32;
    const iv = [_]u8{0x22} ** 16;
    const challenge = Challenge{ .request_nonce = [_]u8{0x33} ** 12, .id_nonce = [_]u8{0x44} ** 16, .enr_sequence = 258 };
    const packet = encodeWhoAreYou(destination_id, iv, challenge);
    try std.testing.expectEqual(@as(usize, 63), packet.len);
    var expected_mask: [47]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_mask, "697f37fc4ffd38ea8bf0ba14e7e5235492a848a5adc84b083ba4e94c6d1c19fc92b5118f191469931a40f8c27f4ed3");
    try std.testing.expectEqualSlices(u8, &expected_mask, packet[16..]);
    try std.testing.expectEqual(Kind.whoareyou, (try inspect(destination_id, &packet)).kind);
    try std.testing.expectEqualDeep(challenge, try decodeWhoAreYou(destination_id, &packet));
    try std.testing.expectError(error.InvalidPacketHeader, decodeWhoAreYou([_]u8{0x12} ** 32, &packet));
    try std.testing.expectError(error.InvalidPacketSize, inspect(destination_id, packet[0..62]));
    var trailing: [64]u8 = undefined;
    @memcpy(trailing[0..63], &packet);
    trailing[63] = 0;
    try std.testing.expectError(error.InvalidPacketHeader, inspect(destination_id, &trailing));
}

test "ordinary packet authenticates discv5 plaintext and rejects tampering" {
    const messages = @import("discv5_messages.zig");
    const allocator = std.testing.allocator;
    const destination_id = [_]u8{0x11} ** 32;
    const source_id = [_]u8{0x55} ** 32;
    const key = [_]u8{0x66} ** 16;
    const nonce = [_]u8{0x33} ** 12;
    const request_id = try messages.RequestId.init(&.{ 1, 2, 3 });
    const plaintext = try messages.encode(allocator, .{ .ping = .{ .request_id = request_id, .enr_sequence = 7 } });
    defer allocator.free(plaintext);
    const packet = try encodeOrdinary(allocator, destination_id, source_id, [_]u8{0x22} ** 16, nonce, key, plaintext);
    defer allocator.free(packet);
    var expected_ciphertext_and_tag: [23]u8 = undefined;
    // Independently calculated with Python cryptography's AESGCM.
    _ = try std.fmt.hexToBytes(&expected_ciphertext_and_tag, "5c4d5ab218b91920cca0ef343508dbc233b9b7d3fbc60c");
    try std.testing.expectEqualSlices(u8, &expected_ciphertext_and_tag, packet[iv_size + static_header_size + ordinary_auth_size ..]);
    try std.testing.expectEqual(Kind.ordinary, (try inspect(destination_id, packet)).kind);
    const decoded = try decodeOrdinary(allocator, destination_id, key, packet);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(source_id, decoded.source_id);
    try std.testing.expectEqual(nonce, decoded.nonce);
    try std.testing.expectEqualSlices(u8, plaintext, decoded.plaintext);
    try std.testing.expectEqual(@as(u64, 7), (try messages.decode(allocator, decoded.plaintext)).ping.enr_sequence);
    const tampered = try allocator.dupe(u8, packet);
    defer allocator.free(tampered);
    tampered[iv_size + static_header_size + ordinary_auth_size] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, decodeOrdinary(allocator, destination_id, key, tampered));
    tampered[iv_size + static_header_size + ordinary_auth_size] ^= 1;
    tampered[iv_size + static_header_size] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, decodeOrdinary(allocator, destination_id, key, tampered));
    try std.testing.expectError(error.AuthenticationFailed, decodeOrdinary(allocator, destination_id, [_]u8{0x67} ** 16, packet));
    try std.testing.expectError(error.InvalidPacketHeader, decodeOrdinary(allocator, [_]u8{0x12} ** 32, key, packet));
    try std.testing.expectError(error.InvalidMessageSize, encodeOrdinary(allocator, destination_id, source_id, [_]u8{0x22} ** 16, nonce, key, &([_]u8{0} ** (max_packet_size - ordinary_overhead + 1))));
}
