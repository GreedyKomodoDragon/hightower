// RLPx uses secp256k1 ECDH and ECIES only while establishing a TCP session.
// The recipient authenticates ciphertext before decoding the enclosed auth
// packet; its two-byte EIP-8 size prefix is part of the authenticated data.
// Handshake packets are limited to 1024 bytes, including the prefix.
//
// ephemeral key + recipient identity -> ECIES packet -> verified plaintext
const std = @import("std");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Aes = std.crypto.core.aes.Aes128;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const overhead = 65 + 16 + 32;
pub const max_packet_size = 1024;

/// Encrypt a bounded EIP-8 body to a verified remote static identity.
pub fn encrypt(allocator: std.mem.Allocator, recipient: Ecdsa.PublicKey, ephemeral: Ecdsa.KeyPair, iv: [16]u8, plaintext: []const u8) ![]u8 {
    if (plaintext.len + overhead + 2 > max_packet_size) return error.HandshakeTooLarge;
    const size: u16 = @intCast(plaintext.len + overhead);
    const result = try allocator.alloc(u8, 2 + size);
    errdefer allocator.free(result);
    std.mem.writeInt(u16, result[0..2], size, .big);
    const ephemeral_public = ephemeral.public_key.toUncompressedSec1();
    @memcpy(result[2..67], &ephemeral_public);
    @memcpy(result[67..83], &iv);
    @memcpy(result[83 .. 83 + plaintext.len], plaintext);
    const shared = try agree(ephemeral.secret_key, recipient);
    const keys = keyMaterial(shared);
    crypt(result[83 .. 83 + plaintext.len], keys[0..16].*, iv);
    const tag = mac(keys[16..32].*, result[0 .. 83 + plaintext.len], plaintext.len);
    @memcpy(result[83 + plaintext.len ..], &tag);
    return result;
}

/// Authenticate and decrypt one complete EIP-8 packet; the caller frees its plaintext.
pub fn decrypt(allocator: std.mem.Allocator, recipient: Ecdsa.SecretKey, packet: []const u8) ![]u8 {
    if (packet.len < 2 + overhead or packet.len > max_packet_size) return error.InvalidHandshakeSize;
    const size = std.mem.readInt(u16, packet[0..2], .big);
    if (size != packet.len - 2) return error.InvalidHandshakeSize;
    const public = Ecdsa.PublicKey.fromSec1(packet[2..67]) catch return error.InvalidEphemeralKey;
    const shared = try agree(recipient, public);
    const keys = keyMaterial(shared);
    const message_len = packet.len - 2 - overhead;
    const expected = mac(keys[16..32].*, packet[0 .. 83 + message_len], message_len);
    if (!std.crypto.timing_safe.eql([32]u8, expected, packet[83 + message_len ..][0..32].*)) return error.InvalidHandshakeMac;
    const result = try allocator.dupe(u8, packet[83 .. 83 + message_len]);
    crypt(result, keys[0..16].*, packet[67..83].*);
    return result;
}

/// Derive the shared X coordinate of a secp256k1 point multiplication.
pub fn agree(secret: Ecdsa.SecretKey, public: Ecdsa.PublicKey) ![32]u8 {
    const shared = try public.p.mul(secret.bytes, .big);
    return shared.toUncompressedSec1()[1..33].*;
}

/// Derive AES and HMAC seed bytes with the RLPx concatenation KDF.
fn keyMaterial(shared: [32]u8) [32]u8 {
    var input: [36]u8 = undefined;
    std.mem.writeInt(u32, input[0..4], 1, .big);
    @memcpy(input[4..], &shared);
    var material: [32]u8 = undefined;
    Sha256.hash(&input, &material, .{});
    return material;
}

/// Authenticate the IV, ciphertext, and EIP-8 size prefix in wire order.
fn mac(seed: [16]u8, packet_prefix: []const u8, message_len: usize) [32]u8 {
    var key: [32]u8 = undefined;
    Sha256.hash(&seed, &key, .{});
    var state = Hmac.init(&key);
    state.update(packet_prefix[67 .. 83 + message_len]);
    state.update(packet_prefix[0..2]);
    var result: [32]u8 = undefined;
    state.final(&result);
    return result;
}

/// XOR a handshake body with AES-128-CTR using the transmitted IV.
fn crypt(bytes: []u8, key: [16]u8, iv: [16]u8) void {
    const aes = Aes.initEnc(key);
    var counter = iv;
    var block: [16]u8 = undefined;
    var offset: usize = 16;
    for (bytes) |*byte| {
        if (offset == 16) {
            aes.encrypt(&block, &counter);
            var i: usize = counter.len;
            while (i > 0) {
                i -= 1;
                counter[i] +%= 1;
                if (counter[i] != 0) break;
            }
            offset = 0;
        }
        byte.* ^= block[offset];
        offset += 1;
    }
}

test "ECIES decrypts a signed peer packet and rejects a changed prefix or MAC" {
    const a = std.testing.allocator;
    const alice = try Ecdsa.KeyPair.generateDeterministic(.{1} ** 32);
    const bob = try Ecdsa.KeyPair.generateDeterministic(.{2} ** 32);
    const ephemeral = try Ecdsa.KeyPair.generateDeterministic(.{3} ** 32);
    const wire = try encrypt(a, bob.public_key, ephemeral, .{4} ** 16, "rlpx auth");
    defer a.free(wire);
    const plaintext = try decrypt(a, bob.secret_key, wire);
    defer a.free(plaintext);
    try std.testing.expectEqualStrings("rlpx auth", plaintext);
    try std.testing.expectError(error.InvalidHandshakeMac, decrypt(a, alice.secret_key, wire));
    wire[0] ^= 1;
    try std.testing.expectError(error.InvalidHandshakeSize, decrypt(a, bob.secret_key, wire));
}
