// Libp2p Noise XX encrypts its static X25519 keys during the handshake. The
// encrypted payload binds each Noise static key to a secp256k1 libp2p identity
// signature; compare that identity with the verified ENR before admitting a
// discovered peer. A canonical public-key protobuf and low-S DER signature
// prevent alternate encodings of the same identity.
//
//   verified ENR key -> Noise static-key signature -> authenticated peer
// This module handles the identity payload only. A Noise XX handshake must
// encrypt and verify it before any application stream bytes are accepted.
const std = @import("std");
const enr = @import("enr.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Scalar = std.crypto.ecc.Secp256k1.scalar;
const signature_prefix = "noise-libp2p-static-key:";
const public_key_prefix = [_]u8{ 0x08, 0x02, 0x12, 0x21 };
const public_key_size = public_key_prefix.len + 33;
const max_signature_size = Ecdsa.Signature.der_encoded_length_max;
const encoded_capacity = 2 + public_key_size + 2 + max_signature_size;
pub const max_payload_size = 1024;

pub const Payload = struct {
    bytes: [encoded_capacity]u8,
    len: usize,

    /// Borrow the encoded protobuf bytes until this value is replaced.
    pub fn slice(self: *const Payload) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Sign one Noise static public key with the same secp256k1 identity as the ENR.
pub fn encode(identity: Ecdsa.KeyPair, noise_static_key: [32]u8) !Payload {
    const message = signature_prefix.* ++ noise_static_key;
    var signature = try identity.sign(&message, null);
    if (std.mem.readInt(u256, &signature.s, .big) > Scalar.field_order / 2) {
        signature.s = try Scalar.neg(signature.s, .big);
    }
    var der_buffer: [max_signature_size]u8 = undefined;
    const der = signature.toDer(&der_buffer);
    var payload: Payload = .{ .bytes = undefined, .len = 2 + public_key_size + 2 + der.len };
    payload.bytes[0] = 0x0a;
    payload.bytes[1] = public_key_size;
    @memcpy(payload.bytes[2..][0..public_key_prefix.len], &public_key_prefix);
    const public_key = identity.public_key.toCompressedSec1();
    @memcpy(payload.bytes[2 + public_key_prefix.len ..][0..public_key.len], &public_key);
    const signature_offset = 2 + public_key_size;
    payload.bytes[signature_offset] = 0x12;
    payload.bytes[signature_offset + 1] = @intCast(der.len);
    @memcpy(payload.bytes[signature_offset + 2 ..][0..der.len], der);
    return payload;
}

/// Authenticate a decrypted Noise payload against a signature-verified ENR.
/// The caller must first verify the ENR and bind its node ID to the peer being dialed.
pub fn verify(payload: []const u8, noise_static_key: [32]u8, expected: enr.Record) !void {
    if (payload.len > max_payload_size) return error.PayloadTooLarge;
    var offset: usize = 0;
    if (offset == payload.len or payload[offset] != 0x0a) return error.InvalidIdentityPayload;
    offset += 1;
    const key_len = try readLength(payload, &offset);
    if (key_len != public_key_size or key_len > payload.len - offset) return error.InvalidIdentityPayload;
    const key = payload[offset..][0..key_len];
    offset += key_len;
    if (!std.mem.eql(u8, key[0..public_key_prefix.len], &public_key_prefix)) return error.InvalidIdentityPayload;
    if (!std.mem.eql(u8, key[public_key_prefix.len..], &expected.public_key)) return error.InvalidIdentity;
    if (offset == payload.len or payload[offset] != 0x12) return error.InvalidIdentityPayload;
    offset += 1;
    const signature_len = try readLength(payload, &offset);
    if (signature_len == 0 or signature_len > max_signature_size or signature_len > payload.len - offset) return error.InvalidIdentityPayload;
    const der = payload[offset..][0..signature_len];
    offset += signature_len;
    if (offset < payload.len) {
        if (payload[offset] != 0x22) return error.InvalidIdentityPayload;
        offset += 1;
        const extension_len = try readLength(payload, &offset);
        if (extension_len != payload.len - offset) return error.InvalidIdentityPayload;
    }
    const signature = Ecdsa.Signature.fromDer(der) catch return error.InvalidIdentityPayload;
    if (std.mem.readInt(u256, &signature.r, .big) == 0 or std.mem.readInt(u256, &signature.s, .big) == 0) return error.InvalidIdentityPayload;
    var canonical: [max_signature_size]u8 = undefined;
    if (!std.mem.eql(u8, der, signature.toDer(&canonical))) return error.InvalidIdentityPayload;
    if (std.mem.readInt(u256, &signature.s, .big) > Scalar.field_order / 2) return error.NonCanonicalSignature;
    const public_key = try Ecdsa.PublicKey.fromSec1(&expected.public_key);
    const message = signature_prefix.* ++ noise_static_key;
    try signature.verify(&message, public_key);
}

/// Read a canonical protobuf length bounded to two bytes for this payload.
fn readLength(bytes: []const u8, offset: *usize) !usize {
    if (offset.* == bytes.len) return error.InvalidIdentityPayload;
    const first = bytes[offset.*];
    offset.* += 1;
    if (first < 0x80) return first;
    if (offset.* == bytes.len) return error.InvalidIdentityPayload;
    const second = bytes[offset.*];
    offset.* += 1;
    if (second == 0 or second > max_payload_size >> 7) return error.InvalidIdentityPayload;
    const length = @as(usize, first & 0x7f) | (@as(usize, second) << 7);
    if (length > max_payload_size) return error.InvalidIdentityPayload;
    return length;
}

test "Noise identity payload binds static key to the signed ENR" {
    const allocator = std.testing.allocator;
    const identity = try Ecdsa.KeyPair.generateDeterministic([_]u8{51} ** 32);
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 9000, .tcp_port = 9001, .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = @import("data_columns.zig").custody_requirement };
    const encoded_enr = try enr.encode(allocator, identity, local);
    defer allocator.free(encoded_enr);
    const record = try enr.decode(allocator, encoded_enr);
    const static_key = [_]u8{31} ** 32;
    const payload = try encode(identity, static_key);
    try verify(payload.slice(), static_key, record);
    try std.testing.expectEqualSlices(u8, &public_key_prefix, payload.slice()[2 .. 2 + public_key_prefix.len]);
    try std.testing.expectError(error.SignatureVerificationFailed, verify(payload.slice(), [_]u8{32} ** 32, record));
    var wrong_identity = record;
    wrong_identity.public_key = (try Ecdsa.KeyPair.generateDeterministic([_]u8{52} ** 32)).public_key.toCompressedSec1();
    try std.testing.expectError(error.InvalidIdentity, verify(payload.slice(), static_key, wrong_identity));
    var altered = payload;
    altered.bytes[altered.len - 1] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, verify(altered.slice(), static_key, record));
}

test "Noise identity payload rejects malformed and noncanonical protobuf" {
    const allocator = std.testing.allocator;
    const identity = try Ecdsa.KeyPair.generateDeterministic([_]u8{53} ** 32);
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 9000, .tcp_port = 9001, .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = @import("data_columns.zig").custody_requirement };
    const encoded_enr = try enr.encode(allocator, identity, local);
    defer allocator.free(encoded_enr);
    const record = try enr.decode(allocator, encoded_enr);
    const static_key = [_]u8{31} ** 32;
    const payload = try encode(identity, static_key);
    var duplicate = payload;
    duplicate.bytes[duplicate.len] = 0x12;
    duplicate.len += 1;
    try std.testing.expectError(error.InvalidIdentityPayload, verify(duplicate.slice(), static_key, record));
    var bad_key = payload;
    bad_key.bytes[3] = 1;
    try std.testing.expectError(error.InvalidIdentityPayload, verify(bad_key.slice(), static_key, record));
    var bad_der = payload;
    bad_der.bytes[2 + public_key_size + 2] = 0;
    try std.testing.expectError(error.InvalidIdentityPayload, verify(bad_der.slice(), static_key, record));
    const with_extension = try allocator.alloc(u8, payload.len + 3);
    defer allocator.free(with_extension);
    @memcpy(with_extension[0..payload.len], payload.slice());
    @memcpy(with_extension[payload.len..], &[_]u8{ 0x22, 1, 0 });
    try verify(with_extension, static_key, record);
    const signature_offset = 2 + public_key_size + 2;
    const original_signature = try Ecdsa.Signature.fromDer(payload.slice()[signature_offset..]);
    var high_signature = original_signature;
    high_signature.s = try Scalar.neg(original_signature.s, .big);
    var high_der_buffer: [max_signature_size]u8 = undefined;
    const high_der = high_signature.toDer(&high_der_buffer);
    var high_payload = payload;
    high_payload.bytes[signature_offset - 1] = @intCast(high_der.len);
    @memcpy(high_payload.bytes[signature_offset..][0..high_der.len], high_der);
    high_payload.len = signature_offset + high_der.len;
    try std.testing.expectError(error.NonCanonicalSignature, verify(high_payload.slice(), static_key, record));
    var zero_component = payload;
    const zero_der = [_]u8{ 0x30, 6, 0x02, 1, 0, 0x02, 1, 1 };
    zero_component.bytes[signature_offset - 1] = zero_der.len;
    @memcpy(zero_component.bytes[signature_offset..][0..zero_der.len], &zero_der);
    zero_component.len = signature_offset + zero_der.len;
    try std.testing.expectError(error.InvalidIdentityPayload, verify(zero_component.slice(), static_key, record));
    try std.testing.expectError(error.PayloadTooLarge, verify(&([_]u8{0} ** (max_payload_size + 1)), static_key, record));
}
